rule TTP_XOR_QUAD_CurrentVersionRun_1897 {
  strings:
    $key_1897 = { 4b f8 [2] 6f f6 [2] 44 da [2] 6a f8 [2] 7e e3 [2] 71 f9 [2] 6f e4 [2] 6d e5 [2] 76 e3 [2] 6a e4 [2] 76 cb }

  condition:
    any of them
}