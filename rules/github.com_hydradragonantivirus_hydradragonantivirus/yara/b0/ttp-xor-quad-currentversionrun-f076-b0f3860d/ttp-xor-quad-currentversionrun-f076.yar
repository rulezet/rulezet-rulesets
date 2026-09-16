rule TTP_XOR_QUAD_CurrentVersionRun_f076 {
  strings:
    $key_f076 = { a3 19 [2] 87 17 [2] ac 3b [2] 82 19 [2] 96 02 [2] 99 18 [2] 87 05 [2] 85 04 [2] 9e 02 [2] 82 05 [2] 9e 2a }

  condition:
    any of them
}