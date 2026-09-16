rule TTP_XOR_QUAD_CurrentVersionRun_acb9 {
  strings:
    $key_acb9 = { ff d6 [2] db d8 [2] f0 f4 [2] de d6 [2] ca cd [2] c5 d7 [2] db ca [2] d9 cb [2] c2 cd [2] de ca [2] c2 e5 }

  condition:
    any of them
}