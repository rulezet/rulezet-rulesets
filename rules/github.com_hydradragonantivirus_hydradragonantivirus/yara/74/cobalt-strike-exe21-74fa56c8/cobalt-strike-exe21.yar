import "pe"
rule cobalt_strike_exe21 {
  meta:
    description = "files -  21.exe"
    author      = "TheDFIRReport"
    date        = "2021-07-25"
    hash1       = "972e38f7fa4c3c59634155debb6fb32eebda3c0e8e73f4cb264463708d378c39"

  strings:
    $s1  = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii
    $s2  = "  VirtualQuery failed for %d bytes at address %p" fullword ascii
    $s3  = "1brrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrr" ascii
    $s4  = "\\hzA\\Vza\\|z%\\2z/\\3z\"\\/z%\\/z8\\9z\"\\(zl\\3z\"\\9z4\\5z8\\|z.\\9z+\\5z\"\\qz)\\2z(\\|z:\\=z>\\5z-\\>z \\9z?\\QzF\\\\zL\\" fullword ascii
    $s5  = "\\zL\\/z>\\qz.\\=za\\0z-\\(z\"\\\\zL\\/z>\\qz?\\,za\\?z5\\.z \\\\zL\\/z>\\qz?\\,za\\0z-\\(z\"\\\\zL\\/z:\\qz*\\5zL\\\\zL\\/z:\\q" ascii
    $s6  = "\\zL:\\zL" fullword ascii
    $s7  = "\\\\z:\\\\z" fullword ascii
    $s8  = "\\qz/\\3z!\\,z%\\0z)\\8zl\\tzc\\?z \\.ze\\|z*\\)z\"\\?z8\\5z#\\2zl\\:z>\\3z!\\|z-\\|z\"\\=z8\\5z:\\9zl\\?z#\\2z?\\(z>\\)z/\\(z#" ascii
    $s9  = "qz<\\%zL\\\\zL\\9z?\\qz?\\*zL\\\\zL\\9z?\\qz9\\%zL\\\\zL\\9z?\\qz:\\9zL\\\\zL\\9z8\\qz)\\9zL\\\\zL\\9z9\\qz)\\/zL\\\\zL\\:z-\\qz" ascii
    $s10 = "zL\\\\zL\\0z:\\qz" fullword ascii
    $s11 = "z-\\(z\"\\\\zL\\/z:\\qz" fullword ascii
    $s12 = "  VirtualProtect failed with code 0x%x" fullword ascii
    $s13 = "3\\)z'\\\\zL\\>z)\\\\zL\\/z \\\\zL\\9z8\\\\zL\\0z:\\\\zL\\0z8\\\\zL\\:z-\\\\zL\\*z%\\\\zL\\4z5\\\\zL\\=z6\\\\zL\\9z9\\\\zL\\1z'" ascii
    $s14 = "z#\\\\zL\\,z \\\\zL\\,z8\\\\zL\\.z#\\\\zL\\.z9\\\\zL\\4z>\\\\zL\\/z'\\\\zL\\/z=\\\\zL\\/z:\\\\zL\\(z$\\\\zL\\(z>\\\\zL\\)z>\\\\z" ascii
    $s15 = "qz \\5zL\\\\zL\\8z)\\qz \\)zL\\\\zL\\8z%\\*za\\1z:\\\\zL\\9z \\qz+\\.zL\\\\zL\\9z\"\\qz-\\)zL\\\\zL\\9z\"\\qz.\\&zL\\\\zL\\9z\"" ascii
    $s16 = "qz<\\7zL\\\\zL\\)z6\\qz9\\&za\\?z5\\.z \\\\zL\\)z6\\qz9\\&za\\0z-\\(z\"\\\\zL\\*z%\\qz:\\2zL\\\\zL\\$z$\\qz6\\=zL\\\\zL\\&z$\\qz" ascii
    $s17 = "qz'\\.zL\\\\zL\\7z5\\qz'\\;zL\\\\zL\\0z8\\qz \\(zL\\\\zL\\0z:\\qz \\*zL\\\\zL\\1z%\\qz\"\\&zL\\\\zL\\1z'\\qz!\\7zL\\\\zL\\1z \\q" ascii
    $s18 = "]zL\\=z*\\qz6\\=zL\\\\zL\\=z>\\qz-\\9zL\\\\zL\\=z>\\qz.\\4zL\\\\zL\\=z>\\qz(\\&zL\\\\zL\\=z>\\qz)\\;zL\\\\zL\\=z>\\qz%\\-zL\\\\z" ascii
    $s19 = "  Unknown pseudo relocation protocol version %d." fullword ascii
    $s20 = "\\L*L\\]qN\\WHKl]qO\\W{j\\XJL\\][G\\}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 800KB and (pe.imphash() == "17b461a082950fc6332228572138b80c" or
      8 of them)
}