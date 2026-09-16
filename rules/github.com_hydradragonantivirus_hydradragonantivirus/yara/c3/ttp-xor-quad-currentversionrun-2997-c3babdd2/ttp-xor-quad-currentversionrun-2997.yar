rule TTP_XOR_QUAD_CurrentVersionRun_2997 {
  strings:
    $key_2997 = { 7a f8 [2] 5e f6 [2] 75 da [2] 5b f8 [2] 4f e3 [2] 40 f9 [2] 5e e4 [2] 5c e5 [2] 47 e3 [2] 5b e4 [2] 47 cb }

  condition:
    any of them
}