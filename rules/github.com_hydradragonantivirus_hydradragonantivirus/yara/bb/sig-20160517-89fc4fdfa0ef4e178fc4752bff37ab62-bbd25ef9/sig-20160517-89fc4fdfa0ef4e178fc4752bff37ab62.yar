rule sig_20160517_89fc4fdfa0ef4e178fc4752bff37ab62 {
  meta:
    description = "datamaliciousorder - file 20160517_89fc4fdfa0ef4e178fc4752bff37ab62.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4927f9eaec98081133af0326af8b13d93ac44f40288f09dcd46867c968280180"

  strings:
    $s1 = "var she='vfmpgsaig4ulrvszlx jbw4ute1beeunnpcxagnkbxhuhdgc2xqytbnenhsrjaargj2xl1pr=fbeig\\'yprkztwdqw1citodmndiq2tia3e4rfg2xfjucl" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}