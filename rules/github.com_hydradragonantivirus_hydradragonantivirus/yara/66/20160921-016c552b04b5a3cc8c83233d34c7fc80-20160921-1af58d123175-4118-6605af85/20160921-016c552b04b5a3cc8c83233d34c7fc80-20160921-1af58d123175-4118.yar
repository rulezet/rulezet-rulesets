rule _20160921_016c552b04b5a3cc8c83233d34c7fc80_20160921_1af58d123175_4118 {
  meta:
    description = "datamaliciousorder - from files 20160921_016c552b04b5a3cc8c83233d34c7fc80.js, 20160921_1af58d1231756b320d04226685b5a131.js, 20160921_7cd473b59463126782b9a6cfaae72835.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a691692f0982e93fd21c441e8c6d39328f1ea5990ce24999b2df98ee3488f667"
    hash2       = "de59166ad132c3c5ad12a85d2d837c1aec192afb497be23c517c637a08d25171"
    hash3       = "0e3e3663f9696265255bc848bc98ec77487c491ee2a30b3085dbc10087b935c5"

  strings:
    $s1 = "ion f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Oe\";})(),(function f000(){return " ascii
    $s2 = "rn \"TKp\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s3 = "on f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s4 = "000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc" ascii
    $s5 = "function f000(){return \"WIj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}