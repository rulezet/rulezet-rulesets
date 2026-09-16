rule TTP_XOR_QUAD_CurrentVersionRun_e585 {
  strings:
    $key_e585 = { b6 ea [2] 92 e4 [2] b9 c8 [2] 97 ea [2] 83 f1 [2] 8c eb [2] 92 f6 [2] 90 f7 [2] 8b f1 [2] 97 f6 [2] 8b d9 }

  condition:
    any of them
}