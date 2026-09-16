rule TTP_XOR_QUAD_CurrentVersionRun_0723 {
  strings:
    $key_0723 = { 54 4c [2] 70 42 [2] 5b 6e [2] 75 4c [2] 61 57 [2] 6e 4d [2] 70 50 [2] 72 51 [2] 69 57 [2] 75 50 [2] 69 7f }

  condition:
    any of them
}