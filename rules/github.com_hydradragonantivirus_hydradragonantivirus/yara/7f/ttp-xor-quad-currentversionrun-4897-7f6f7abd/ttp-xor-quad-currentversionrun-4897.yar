rule TTP_XOR_QUAD_CurrentVersionRun_4897 {
  strings:
    $key_4897 = { 1b f8 [2] 3f f6 [2] 14 da [2] 3a f8 [2] 2e e3 [2] 21 f9 [2] 3f e4 [2] 3d e5 [2] 26 e3 [2] 3a e4 [2] 26 cb }

  condition:
    any of them
}