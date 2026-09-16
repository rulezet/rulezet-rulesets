rule _20160921_6d45b48d21435a8cdd305a8a7d2405a3_20160921_8843826fc0ae_3888 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d45b48d21435a8cdd305a8a7d2405a3.js, 20160921_8843826fc0ae466921b7811b54d8314e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa45b1317b967bb6337124692b84f1082b2294f82eaae64362d2c8cac37b2779"
    hash2       = "78595fd8fc9b77e9ad7cb382c7d0ec855211116626b883d04155604a9a99eab3"

  strings:
    $s1 = "n f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"" ascii
    $s2 = "000(){return \"BMj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz" ascii
    $s3 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})(),(function " ascii
    $s4 = "Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Oe\";})(),(functio" ascii
    $s5 = "(function f000(){return \"MKa\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s6 = "Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}