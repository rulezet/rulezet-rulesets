rule TTP_XOR_QUAD_CurrentVersionRun_adb9 {
  strings:
    $key_adb9 = { fe d6 [2] da d8 [2] f1 f4 [2] df d6 [2] cb cd [2] c4 d7 [2] da ca [2] d8 cb [2] c3 cd [2] df ca [2] c3 e5 }

  condition:
    any of them
}