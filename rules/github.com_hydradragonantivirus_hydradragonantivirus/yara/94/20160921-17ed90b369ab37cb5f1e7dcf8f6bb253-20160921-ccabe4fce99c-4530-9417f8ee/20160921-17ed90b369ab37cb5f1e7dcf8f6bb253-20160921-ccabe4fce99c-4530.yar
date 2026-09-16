rule _20160921_17ed90b369ab37cb5f1e7dcf8f6bb253_20160921_ccabe4fce99c_4530 {
  meta:
    description = "datamaliciousorder - from files 20160921_17ed90b369ab37cb5f1e7dcf8f6bb253.js, 20160921_ccabe4fce99c1ebb627aa374a501f33c.js, 20160921_e985c90f8141417e484ad0056c9b809c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81de0ae14e0c288b697a0e3c7f3ced9b68b8377e75dff5322d654841e642a8a7"
    hash2       = "449fe576ee25f77acba5442d771e770819941d7dbf354b5123ca5211ef743189"
    hash3       = "513b80dc65238dcfcb80f0e8e4f456645bf345b2dde46805b001c07bc579d4c9"

  strings:
    $s1 = "{return \"Sq\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"UEg\";})(" ascii
    $s2 = ",(function f000(){return \"Tn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MDb\";})(),(function f000(){" ascii
    $s3 = "rn \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DNa\";})(),(f" ascii
    $s4 = "f000(){return \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DN" ascii
    $s5 = " \"GGn\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}