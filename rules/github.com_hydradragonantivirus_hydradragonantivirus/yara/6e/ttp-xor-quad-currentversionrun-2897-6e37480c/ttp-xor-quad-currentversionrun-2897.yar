rule TTP_XOR_QUAD_CurrentVersionRun_2897 {
  strings:
    $key_2897 = { 7b f8 [2] 5f f6 [2] 74 da [2] 5a f8 [2] 4e e3 [2] 41 f9 [2] 5f e4 [2] 5d e5 [2] 46 e3 [2] 5a e4 [2] 46 cb }

  condition:
    any of them
}