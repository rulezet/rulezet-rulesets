rule TTP_XOR_QUAD_CurrentVersionRun_6b36 {
  strings:
    $key_6b36 = { 38 59 [2] 1c 57 [2] 37 7b [2] 19 59 [2] 0d 42 [2] 02 58 [2] 1c 45 [2] 1e 44 [2] 05 42 [2] 19 45 [2] 05 6a }

  condition:
    any of them
}