rule TTP_XOR_QUAD_CurrentVersionRun_f697 {
  strings:
    $key_f697 = { a5 f8 [2] 81 f6 [2] aa da [2] 84 f8 [2] 90 e3 [2] 9f f9 [2] 81 e4 [2] 83 e5 [2] 98 e3 [2] 84 e4 [2] 98 cb }

  condition:
    any of them
}