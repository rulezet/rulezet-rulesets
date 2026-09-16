rule sig_20161206_76907ad93d741073ebd9b27a5fdf2c4f {
  meta:
    description = "datamaliciousorder - file 20161206_76907ad93d741073ebd9b27a5fdf2c4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20ae8d4542ac31c468e3cf726cedf68c781787ee4831d08433fc34cb6109dc65"

  strings:
    $s1 = "var vFg6 = new Function(\"s\", '{var vPZc4 = new Date();vPZc4[\"setUTCFullYear\"](\"2003\");if (vPZc4.getUTCFullYear().toString(" ascii
    $s2 = "var vFg6 = new Function(\"s\", '{var vPZc4 = new Date();vPZc4[\"setUTCFullYear\"](\"2003\");if (vPZc4.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vMv9 = s.split(\"##\"); return vMv9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vXOz0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}