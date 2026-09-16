rule TTP_XOR_QUAD_CurrentVersionRun_ad88 {
  strings:
    $key_ad88 = { fe e7 [2] da e9 [2] f1 c5 [2] df e7 [2] cb fc [2] c4 e6 [2] da fb [2] d8 fa [2] c3 fc [2] df fb [2] c3 d4 }

  condition:
    any of them
}