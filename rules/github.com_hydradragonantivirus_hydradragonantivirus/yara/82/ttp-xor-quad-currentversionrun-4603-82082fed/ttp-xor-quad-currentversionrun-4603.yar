rule TTP_XOR_QUAD_CurrentVersionRun_4603 {
  strings:
    $key_4603 = { 15 6c [2] 31 62 [2] 1a 4e [2] 34 6c [2] 20 77 [2] 2f 6d [2] 31 70 [2] 33 71 [2] 28 77 [2] 34 70 [2] 28 5f }

  condition:
    any of them
}