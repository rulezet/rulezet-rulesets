rule _20160921_e0e06f5c94b0cde962f3e4c452e69af8_20160921_fd5fc0674575_5721 {
  meta:
    description = "datamaliciousorder - from files 20160921_e0e06f5c94b0cde962f3e4c452e69af8.js, 20160921_fd5fc067457571e92a95bd16158d41e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9140c7affc44d690abfb95dc146d3e298e2cfddacedfee85549119f368d56d1"
    hash2       = "e32ed831874bb280ae970e019573b598cf97788865b3fea13118546e435353f9"

  strings:
    $s1 = ";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Tn\";})(),(function f0" ascii
    $s2 = "n f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UEg\";})(),(function f000(){return " ascii
    $s3 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"DYx\";})(),(function f0" ascii
    $s4 = ";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii
    $s5 = "{return \"DYx\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}