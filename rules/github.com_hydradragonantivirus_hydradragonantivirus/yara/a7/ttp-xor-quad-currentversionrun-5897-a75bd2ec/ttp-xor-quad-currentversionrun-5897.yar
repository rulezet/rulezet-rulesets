rule TTP_XOR_QUAD_CurrentVersionRun_5897 {
  strings:
    $key_5897 = { 0b f8 [2] 2f f6 [2] 04 da [2] 2a f8 [2] 3e e3 [2] 31 f9 [2] 2f e4 [2] 2d e5 [2] 36 e3 [2] 2a e4 [2] 36 cb }

  condition:
    any of them
}