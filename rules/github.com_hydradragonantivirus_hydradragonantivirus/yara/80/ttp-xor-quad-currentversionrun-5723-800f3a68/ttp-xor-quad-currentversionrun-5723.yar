rule TTP_XOR_QUAD_CurrentVersionRun_5723 {
  strings:
    $key_5723 = { 04 4c [2] 20 42 [2] 0b 6e [2] 25 4c [2] 31 57 [2] 3e 4d [2] 20 50 [2] 22 51 [2] 39 57 [2] 25 50 [2] 39 7f }

  condition:
    any of them
}