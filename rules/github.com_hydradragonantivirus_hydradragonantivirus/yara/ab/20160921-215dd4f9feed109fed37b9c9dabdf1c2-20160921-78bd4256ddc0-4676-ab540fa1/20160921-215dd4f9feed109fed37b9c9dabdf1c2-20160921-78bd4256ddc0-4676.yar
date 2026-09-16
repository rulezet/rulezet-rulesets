rule _20160921_215dd4f9feed109fed37b9c9dabdf1c2_20160921_78bd4256ddc0_4676 {
  meta:
    description = "datamaliciousorder - from files 20160921_215dd4f9feed109fed37b9c9dabdf1c2.js, 20160921_78bd4256ddc0b384791a12e8ab1fd8a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "710f88c7fda95a8d3e0e04de1ffd81606d227d249d76eb0d7fbeba7a0284a86e"
    hash2       = "c64d081235a424574ab6bbe64470cbee71a700f01b638afac6d0954ebc5cc0a0"

  strings:
    $s1 = "fuck(){return \"LLv\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"X" ascii
    $s2 = "{return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"DAa\";})" ascii
    $s3 = "(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XFd\";}" ascii
    $s4 = " \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Fv\";})(),(fun" ascii
    $s5 = "turn \"Ai\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"LGo\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}