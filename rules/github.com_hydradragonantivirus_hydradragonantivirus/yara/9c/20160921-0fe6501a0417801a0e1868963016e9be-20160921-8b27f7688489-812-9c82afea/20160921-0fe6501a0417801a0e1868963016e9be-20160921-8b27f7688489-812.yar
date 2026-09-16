rule _20160921_0fe6501a0417801a0e1868963016e9be_20160921_8b27f7688489_812 {
  meta:
    description = "datamaliciousorder - from files 20160921_0fe6501a0417801a0e1868963016e9be.js, 20160921_8b27f7688489936aa1cc7fded52f4a64.js, 20160921_d57bd7101328f2bbf1f061a7dab83490.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2926229ccbf6b86ba0ed1aa3ab5b137a43467ffe25d09479a7998c2fdc4b2b30"
    hash2       = "dbf2fa1deb81fd17a55e884848d77b2d3c5d766fed0005f738840703aa8a9dda"
    hash3       = "fa72df41c05c5483fee755296c5d2da37c5e14a015c2aac82e7d9ad428cc2376"

  strings:
    $s1  = ")(),(function f000(){return \"DYx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MMz\";})(),(function f00" ascii
    $s2  = "(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Km\";})(),(function f000(){re" ascii
    $s3  = "t\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function " ascii
    $s4  = "urn \"YTp\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s5  = "){return \"NBs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii
    $s6  = "urn \"Um\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"OMd\";})(),(f" ascii
    $s7  = "ction f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"IAa\";})(),(function f000(){retu" ascii
    $s8  = "Km\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DYs\";})(),(functi" ascii
    $s9  = "Gn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"TRc\";})(),(functi" ascii
    $s10 = ";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"BQb\";})(),(function f00" ascii
    $s11 = "MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(funct" ascii
    $s12 = "(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"PTi\"" ascii
    $s13 = "nction f000(){return \"SGs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){ret" ascii
    $s14 = "n \"Wh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s15 = "on f000(){return \"MMz\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"MDb\";})(),(function f000(){return " ascii
    $s16 = "(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";" ascii
    $s17 = "(){return \"Yz\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";}" ascii
    $s18 = "ion f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return " ascii
    $s19 = "v\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s20 = "(function f000(){return \"Sv\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"KXg\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}