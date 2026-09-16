rule TTP_XOR_QUAD_CurrentVersionRun_2097 {
  strings:
    $key_2097 = { 73 f8 [2] 57 f6 [2] 7c da [2] 52 f8 [2] 46 e3 [2] 49 f9 [2] 57 e4 [2] 55 e5 [2] 4e e3 [2] 52 e4 [2] 4e cb }

  condition:
    any of them
}