rule TTP_XOR_QUAD_CurrentVersionRun_3c97 {
  strings:
    $key_3c97 = { 6f f8 [2] 4b f6 [2] 60 da [2] 4e f8 [2] 5a e3 [2] 55 f9 [2] 4b e4 [2] 49 e5 [2] 52 e3 [2] 4e e4 [2] 52 cb }

  condition:
    any of them
}