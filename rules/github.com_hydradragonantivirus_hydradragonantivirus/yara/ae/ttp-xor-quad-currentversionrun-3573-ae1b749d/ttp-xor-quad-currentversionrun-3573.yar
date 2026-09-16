rule TTP_XOR_QUAD_CurrentVersionRun_3573 {
  strings:
    $key_3573 = { 66 1c [2] 42 12 [2] 69 3e [2] 47 1c [2] 53 07 [2] 5c 1d [2] 42 00 [2] 40 01 [2] 5b 07 [2] 47 00 [2] 5b 2f }

  condition:
    any of them
}