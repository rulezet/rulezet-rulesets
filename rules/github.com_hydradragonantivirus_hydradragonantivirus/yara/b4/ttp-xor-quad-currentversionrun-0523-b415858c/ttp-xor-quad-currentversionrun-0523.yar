rule TTP_XOR_QUAD_CurrentVersionRun_0523 {
  strings:
    $key_0523 = { 56 4c [2] 72 42 [2] 59 6e [2] 77 4c [2] 63 57 [2] 6c 4d [2] 72 50 [2] 70 51 [2] 6b 57 [2] 77 50 [2] 6b 7f }

  condition:
    any of them
}