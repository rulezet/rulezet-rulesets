rule sig_20161220_dc67b5b6b75377f993492c7bd7dac7dd {
  meta:
    description = "datamaliciousorder - file 20161220_dc67b5b6b75377f993492c7bd7dac7dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72d69be0606cbf875f75d0629d28180ca08f36742e80b0e0a6ffdf9d894096e1"

  strings:
    $s1 = "var soqgelpalny = new Function([-991, -19, -531, -182, -332, -15, \"ret\", -540, -425, -388, -975, -444, -331, -919, -711, -891," ascii
    $s2 = "if (new Function([-782, -555, -43, \"va\", -835, -108, -76, -848, -190, -217, -531, -140, -448, -191, -853, -288, -444, -401, -2" ascii
    $s3 = "var soqgelpalny = new Function([-991, -19, -531, -182, -332, -15, \"ret\", -540, -425, -388, -975, -444, -331, -919, -711, -891," ascii
    $s4 = "if (new Function([-782, -555, -43, \"va\", -835, -108, -76, -848, -190, -217, -531, -140, -448, -191, -853, -288, -444, -401, -2" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}