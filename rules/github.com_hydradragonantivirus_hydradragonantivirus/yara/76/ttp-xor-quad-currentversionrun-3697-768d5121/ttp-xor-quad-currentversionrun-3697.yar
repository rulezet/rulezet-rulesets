rule TTP_XOR_QUAD_CurrentVersionRun_3697 {
  strings:
    $key_3697 = { 65 f8 [2] 41 f6 [2] 6a da [2] 44 f8 [2] 50 e3 [2] 5f f9 [2] 41 e4 [2] 43 e5 [2] 58 e3 [2] 44 e4 [2] 58 cb }

  condition:
    any of them
}