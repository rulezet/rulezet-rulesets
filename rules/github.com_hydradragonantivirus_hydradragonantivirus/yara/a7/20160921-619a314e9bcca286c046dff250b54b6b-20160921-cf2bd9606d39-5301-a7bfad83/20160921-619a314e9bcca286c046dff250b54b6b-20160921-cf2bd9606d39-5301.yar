rule _20160921_619a314e9bcca286c046dff250b54b6b_20160921_cf2bd9606d39_5301 {
  meta:
    description = "datamaliciousorder - from files 20160921_619a314e9bcca286c046dff250b54b6b.js, 20160921_cf2bd9606d396ba99f8174f1946c8590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f370548310908c52102d40d56781574ad404eafca7ac832d5e52d48f722bff5"
    hash2       = "c5afd84ebe18fa55c764dd8e7349bc7b9cd8b10ab8d94500cbf7f62bd741c00d"

  strings:
    $s1 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Tn\";})(),(function f000()" ascii
    $s2 = "(){return \"GGn\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";})" ascii
    $s3 = "){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})" ascii
    $s4 = "000(){return \"QDg\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Vu\"" ascii
    $s5 = "on f000(){return \"WIj\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Oe\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}