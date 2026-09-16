rule TTP_XOR_QUAD_CurrentVersionRun_f276 {
  strings:
    $key_f276 = { a1 19 [2] 85 17 [2] ae 3b [2] 80 19 [2] 94 02 [2] 9b 18 [2] 85 05 [2] 87 04 [2] 9c 02 [2] 80 05 [2] 9c 2a }

  condition:
    any of them
}