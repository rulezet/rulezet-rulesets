rule sig_20170219_63673c54626ff8b38eeea5e870c17f8f {
  meta:
    description = "datamaliciousorder - file 20170219_63673c54626ff8b38eeea5e870c17f8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f00eb42dbac0a00e0c4736d99807e73a8bb9b3d1f493b26c25993ee63eecbbcb"

  strings:
    $s1  = "//var mist = [Number(7), [WScript, Number(4), Number(5), Number(1)][0], Number(3), Number(1)][1][ewreqw](ydybit);" fullword ascii
    $s2  = "var yjovg = [Number(7), [WScript, Number(4), Number(5), Number(1)][0], Number(3), Number(1)][1][ewreqw](unapj);" fullword ascii
    $s3  = "var zijboz = [Number(5), \"cmd.\", Number(4), Number(5)];" fullword ascii
    $s4  = "var rxiklo = [\"GetB\", Number(9), Number(8)];" fullword ascii
    $s5  = "var compynx = [Number(5), \"$ywu\"];" fullword ascii
    $s6  = "var abinva = [\"zc='\", Number(2)];" fullword ascii
    $s7  = "var cekojw = [Number(4), Number(9), \"run\"];" fullword ascii
    $s8  = "var comovx = [Number(5), Number(7), Number(8), \"';$h\"];" fullword ascii
    $s9  = "var kytcomc = [Number(3), \"='^t\"];" fullword ascii
    $s10 = "var oxjubi = [Number(9), Number(8), Number(4), \"= ''\"];" fullword ascii
    $s11 = "var mvemlyti = [Number(4), Number(5), \"^lic\"];" fullword ascii
    $s12 = "var udgivitw = [\"$yte\", Number(4), Number(4)];" fullword ascii
    $s13 = "var nopof = [\"';$c\", Number(6), Number(8), Number(3)];" fullword ascii
    $s14 = "var awfytu = [\"e+$x\", Number(6), Number(7), Number(7)];" fullword ascii
    $s15 = "var mjiqnove = [Number(2), Number(1), \";';$\", Number(5)];" fullword ascii
    $s16 = "var ewigo = [Number(5), \"diks\", Number(2), Number(5)];" fullword ascii
    $s17 = "var edagv = [Number(8), Number(8), \"$xgo\", Number(1)];" fullword ascii
    $s18 = "var vroka = [\" B';\", Number(3)];" fullword ascii
    $s19 = "var atsexkuln = [Number(2), \"'^il\", Number(2)];" fullword ascii
    $s20 = "var pepa = [Number(7), \"ulme\", Number(4)];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}