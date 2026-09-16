rule TTP_XOR_QUAD_CurrentVersionRun_0897 {
  strings:
    $key_0897 = { 5b f8 [2] 7f f6 [2] 54 da [2] 7a f8 [2] 6e e3 [2] 61 f9 [2] 7f e4 [2] 7d e5 [2] 66 e3 [2] 7a e4 [2] 66 cb }

  condition:
    any of them
}