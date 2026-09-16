rule _20160921_10f44d7e5dfb0603aa30725d24785246_20160921_b2419a000449_3363 {
  meta:
    description = "datamaliciousorder - from files 20160921_10f44d7e5dfb0603aa30725d24785246.js, 20160921_b2419a000449b12cbd6aff3732baf55d.js, 20160921_ba12dcdd1588a0048542bf1b103073ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ded66def256e0559ce1d6d20e6f8663edec045a58bb8ef0ec1038fbd91f7c7c1"
    hash2       = "ea7b5520c177b4adf74565706c3c8ed38eed94f30b6927b0ceb647f7f768a2b5"
    hash3       = "18a1f3c65d9893a27783cb78ff5cd36c757196e35be1977f03c68231e20d9b44"

  strings:
    $s1 = "on fuck(){return \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return " ascii
    $s2 = "function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){r" ascii
    $s3 = "turn \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IRn\";})()," ascii
    $s4 = "nction fuck(){return \"Ml\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retu" ascii
    $s5 = "(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IPu\";" ascii
    $s6 = "n fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}