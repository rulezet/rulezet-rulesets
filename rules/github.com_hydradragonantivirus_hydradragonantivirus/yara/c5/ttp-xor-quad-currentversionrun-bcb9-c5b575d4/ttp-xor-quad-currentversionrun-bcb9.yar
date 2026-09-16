rule TTP_XOR_QUAD_CurrentVersionRun_bcb9 {
  strings:
    $key_bcb9 = { ef d6 [2] cb d8 [2] e0 f4 [2] ce d6 [2] da cd [2] d5 d7 [2] cb ca [2] c9 cb [2] d2 cd [2] ce ca [2] d2 e5 }

  condition:
    any of them
}