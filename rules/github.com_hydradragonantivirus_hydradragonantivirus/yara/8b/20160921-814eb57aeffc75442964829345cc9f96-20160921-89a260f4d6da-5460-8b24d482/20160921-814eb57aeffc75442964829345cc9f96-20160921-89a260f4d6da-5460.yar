rule _20160921_814eb57aeffc75442964829345cc9f96_20160921_89a260f4d6da_5460 {
  meta:
    description = "datamaliciousorder - from files 20160921_814eb57aeffc75442964829345cc9f96.js, 20160921_89a260f4d6da4d97f251f843cf5e94b0.js, 20160921_98f234a378a6dd4e51c1730a4a700647.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2736df4d651a33824aba7abffa7c08414414ffed9f5f27b4b2d81101cfeb7117"
    hash2       = "700f6c802eb024896efe2b22255973b53752a8f129213c9bba2c4f2ebdc53988"
    hash3       = "67d0e50d586bb8bcc6b12ccab848f1a72b3a329ddaa0c7f45ea3661082887c8d"

  strings:
    $s1 = "{return \"Vj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"SEo\";})(" ascii
    $s2 = "ion f000(){return \"RVb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Uo\";})(),(function f000(){return " ascii
    $s3 = "),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"MBb\";})(),(function f000(" ascii
    $s4 = "turn \"Lp\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s5 = "})(),(function f000(){return \"Oh\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"EZu\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}