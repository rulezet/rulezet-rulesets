rule _20160921_72cf8bebbcf48b45894fe7d7b3327a58_20160921_cb6c4de61b30_2505 {
  meta:
    description = "datamaliciousorder - from files 20160921_72cf8bebbcf48b45894fe7d7b3327a58.js, 20160921_cb6c4de61b30cd204129d0942321058c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "004799df77a97e1e1816f6a4a1acf9bec5dfd13ae07613832796a6c9ef0cc578"
    hash2       = "db98233c2508e4a2167ee46a334ce9052faa726615e89838f4fdb36b74fc5353"

  strings:
    $s1 = "\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"KXg\";})(),(function f" ascii
    $s2 = "function f000(){return \"Lo\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){re" ascii
    $s3 = "\"KXg\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(fun" ascii
    $s4 = "})(),(function f000(){return \"Sv\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000" ascii
    $s5 = "function f000(){return \"IPu\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MBb\";})(),(function f000(){r" ascii
    $s6 = "ion f000(){return \"MDb\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"DYx\";})(),(function f000(){return " ascii
    $s7 = "f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"M" ascii
    $s8 = "),(function f000(){return \"Yz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}