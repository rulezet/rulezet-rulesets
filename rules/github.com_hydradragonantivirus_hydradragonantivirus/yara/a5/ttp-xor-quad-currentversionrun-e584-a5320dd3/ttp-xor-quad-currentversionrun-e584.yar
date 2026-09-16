rule TTP_XOR_QUAD_CurrentVersionRun_e584 {
  strings:
    $key_e584 = { b6 eb [2] 92 e5 [2] b9 c9 [2] 97 eb [2] 83 f0 [2] 8c ea [2] 92 f7 [2] 90 f6 [2] 8b f0 [2] 97 f7 [2] 8b d8 }

  condition:
    any of them
}