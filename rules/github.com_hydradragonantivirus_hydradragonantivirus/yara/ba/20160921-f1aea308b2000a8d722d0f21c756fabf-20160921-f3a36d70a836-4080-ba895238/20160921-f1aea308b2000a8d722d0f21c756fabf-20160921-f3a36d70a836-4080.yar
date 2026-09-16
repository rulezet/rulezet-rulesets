rule _20160921_f1aea308b2000a8d722d0f21c756fabf_20160921_f3a36d70a836_4080 {
  meta:
    description = "datamaliciousorder - from files 20160921_f1aea308b2000a8d722d0f21c756fabf.js, 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3175e432bce3be89acef4ff7215de666ea47cac857c8c07ff649c1cdd5484103"
    hash2       = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"

  strings:
    $s1 = "0(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";}" ascii
    $s2 = "00(){return \"Sq\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"OUx" ascii
    $s3 = "on f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s4 = ")(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s5 = "urn \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(f" ascii
    $s6 = "})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Do\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}