rule TTP_XOR_QUAD_CurrentVersionRun_e897 {
  strings:
    $key_e897 = { bb f8 [2] 9f f6 [2] b4 da [2] 9a f8 [2] 8e e3 [2] 81 f9 [2] 9f e4 [2] 9d e5 [2] 86 e3 [2] 9a e4 [2] 86 cb }

  condition:
    any of them
}