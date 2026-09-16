rule _20160921_d53637406b068b7f313912a4769e371e_20160922_2bdee31da941_1140 {
  meta:
    description = "datamaliciousorder - from files 20160921_d53637406b068b7f313912a4769e371e.js, 20160922_2bdee31da941689170d6b7da303eeff6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cafcf490b9e4364e16ee46f82e53896038b46a0b37f3fd7a33a363316965b400"
    hash2       = "70ee088e40fb9f7bd2cc1514b94af7f28ef9fd68444cdbd3859858840ae0e498"

  strings:
    $s1  = " \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s2  = "000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Zj" ascii
    $s3  = "eturn \"Iq\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()," ascii
    $s4  = "(function f000(){return \"PTi\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BQb\";})(),(function f000(){" ascii
    $s5  = "unction f000(){return \"NBs\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){retu" ascii
    $s6  = "\"QDg\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"SGs\";})(),(fun" ascii
    $s7  = "n f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"RLk\";})(),(function f000(){return " ascii
    $s8  = "n f000(){return \"WIj\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"V" ascii
    $s9  = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"DNa\";})(),(function f0" ascii
    $s10 = "urn \"PTi\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Ml\";})(),(f" ascii
    $s11 = "GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s12 = "ion f000(){return \"IAa\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s13 = "\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(function " ascii
    $s14 = "){return \"DNa\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go\";})" ascii
    $s15 = "00(){return \"ZIi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"DIa" ascii
    $s16 = "00(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"UEg" ascii
    $s17 = "eturn \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Oh\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}