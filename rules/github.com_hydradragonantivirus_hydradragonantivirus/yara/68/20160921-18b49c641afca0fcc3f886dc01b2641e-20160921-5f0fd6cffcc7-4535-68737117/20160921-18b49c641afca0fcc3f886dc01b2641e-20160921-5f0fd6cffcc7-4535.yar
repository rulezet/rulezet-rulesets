rule _20160921_18b49c641afca0fcc3f886dc01b2641e_20160921_5f0fd6cffcc7_4535 {
  meta:
    description = "datamaliciousorder - from files 20160921_18b49c641afca0fcc3f886dc01b2641e.js, 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js, 20160921_8ab8e9ec61d829b3b36dc8e0cbc3b477.js, 20160921_a7532ebefde89d14f64381982f45f5dc.js, 20160921_d860185d3d51e8a363b423c048150940.js, 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a697115d075c4bd09fb1f58699de7b47c8cbea42964865bfac236a14f40a03c5"
    hash2       = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"
    hash3       = "6302a5443fa0c0309aa33e24b90ed81d05258a2a800cda52321e903fc44e0494"
    hash4       = "601a014082c8ae8d379ef7ccf41dbd1f7df2b8e196161905ccc52c5565bf2b04"
    hash5       = "419be2ea8bb0db95703d86253063108b2da68cb9ec72abf96d06bdf5162cc75f"
    hash6       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"

  strings:
    $s1 = "00(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\"" ascii
    $s2 = "rn \"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(fun" ascii
    $s3 = "unction f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(){ret" ascii
    $s4 = "ction f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(function f000(){retur" ascii
    $s5 = "Mj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"RLk\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}