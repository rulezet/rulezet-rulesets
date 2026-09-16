rule _20160921_1ccc6f9d608f6057f34a9f01f0cf5abe_20160921_cebdb99ce2e5_1546 {
  meta:
    description = "datamaliciousorder - from files 20160921_1ccc6f9d608f6057f34a9f01f0cf5abe.js, 20160921_cebdb99ce2e54d24acef5b8ee0096562.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "226d26c073abdcaab4155bb0b8d789289cf0a453f58c9f6383385cc78660a27e"
    hash2       = "87071d18d308dc7717dabe03dc0d11efe7ee7231e95d9fca71e480f5f2430f7d"

  strings:
    $s1  = "000(){return \"IPu\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"ZIi" ascii
    $s2  = "\"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"UEg\";})(),(funct" ascii
    $s3  = "return \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})()" ascii
    $s4  = "ion f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s5  = "ction f000(){return \"WIj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Br\";})(),(function f000(){return" ascii
    $s6  = "unction f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lo\";})(),(function f000(){retu" ascii
    $s7  = "f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc" ascii
    $s8  = ",(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Yv\";})(),(function f000(){r" ascii
    $s9  = "BQb\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s10 = "(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"BMj\";})(),(function f000()" ascii
    $s11 = "eturn \"ZIi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})()," ascii
    $s12 = "ction f000(){return \"Ot\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}