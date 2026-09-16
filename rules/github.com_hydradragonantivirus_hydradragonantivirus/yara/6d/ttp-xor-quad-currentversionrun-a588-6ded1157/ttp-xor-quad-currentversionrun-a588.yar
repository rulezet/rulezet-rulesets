rule TTP_XOR_QUAD_CurrentVersionRun_a588 {
  strings:
    $key_a588 = { f6 e7 [2] d2 e9 [2] f9 c5 [2] d7 e7 [2] c3 fc [2] cc e6 [2] d2 fb [2] d0 fa [2] cb fc [2] d7 fb [2] cb d4 }

  condition:
    any of them
}