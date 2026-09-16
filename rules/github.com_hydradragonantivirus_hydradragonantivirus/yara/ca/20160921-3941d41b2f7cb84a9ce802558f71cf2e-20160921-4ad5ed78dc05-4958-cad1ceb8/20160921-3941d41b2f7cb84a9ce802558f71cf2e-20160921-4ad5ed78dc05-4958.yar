rule _20160921_3941d41b2f7cb84a9ce802558f71cf2e_20160921_4ad5ed78dc05_4958 {
  meta:
    description = "datamaliciousorder - from files 20160921_3941d41b2f7cb84a9ce802558f71cf2e.js, 20160921_4ad5ed78dc05b02005f65ab785b9c74a.js, 20160921_5e3ac68b2242250176f3300039d176f6.js, 20160921_b062b54e33ac394b0c1a389b161f5cb6.js, 20160921_e0e06f5c94b0cde962f3e4c452e69af8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af803579fff33b5e316911dc121155eb553434eec287816287bbd86b427b3f7f"
    hash2       = "7e5f9d362688f19111d3dbdf393d51e133fcc63eb7db27536cb31d1205ccc9e3"
    hash3       = "89b3eb7dc82702c0fd809112cd45d647e28906b665dcfd9718254fadc25580e9"
    hash4       = "5d0516ba7ba35ed307fd316146755f07fe542904a37fc2e0bb6a28a59cb06139"
    hash5       = "c9140c7affc44d690abfb95dc146d3e298e2cfddacedfee85549119f368d56d1"

  strings:
    $s1 = "(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";" ascii
    $s2 = "\"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"MDb\";})(),(funct" ascii
    $s3 = "nction f000(){return \"Nv\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Nx\";})(),(function f000(){retur" ascii
    $s4 = "return \"KDh\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii
    $s5 = ",(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"MDb\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}