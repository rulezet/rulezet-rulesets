rule TTP_XOR_QUAD_CurrentVersionRun_ec97 {
  strings:
    $key_ec97 = { bf f8 [2] 9b f6 [2] b0 da [2] 9e f8 [2] 8a e3 [2] 85 f9 [2] 9b e4 [2] 99 e5 [2] 82 e3 [2] 9e e4 [2] 82 cb }

  condition:
    any of them
}