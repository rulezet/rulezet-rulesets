rule sig_20160525_150c5672f5c5a2b2b2162a538baf3f07 {
  meta:
    description = "datamaliciousorder - file 20160525_150c5672f5c5a2b2b2162a538baf3f07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9de8af7d583ce5289d5a420bfbacfe1cfd08e9d741d0463b346a9e950093389c"

  strings:
    $s1 = "ahc\"[tsilslianbmuhtos = ims rav;\"qhL\" = tsilslianbmuhtos rav\\n;\"tgn56x\\\\l\" = eixodt rav\\n;\"86x\\\\\" = gsmt rav'[\"spl" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}