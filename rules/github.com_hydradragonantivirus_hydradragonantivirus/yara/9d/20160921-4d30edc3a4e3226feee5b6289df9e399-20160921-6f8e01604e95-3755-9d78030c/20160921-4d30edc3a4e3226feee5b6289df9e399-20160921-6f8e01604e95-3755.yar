rule _20160921_4d30edc3a4e3226feee5b6289df9e399_20160921_6f8e01604e95_3755 {
  meta:
    description = "datamaliciousorder - from files 20160921_4d30edc3a4e3226feee5b6289df9e399.js, 20160921_6f8e01604e95009c9405a4a9c31cc901.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d28b5e72375443a9ef1a43fee185a0e5563672a0764eef4f58a90a27302162ea"
    hash2       = "5324b4f5c36c3ebb1567659beec8a89d0c1c954daf56a6131f3aebe46384317b"

  strings:
    $s1 = "(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Vb\";}" ascii
    $s2 = "GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(functio" ascii
    $s3 = "LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(functi" ascii
    $s4 = "{return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MOj\";}" ascii
    $s5 = "k(){return \"CCb\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\"" ascii
    $s6 = "n fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}