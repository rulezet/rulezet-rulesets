rule TTP_XOR_QUAD_CurrentVersionRun_2f03 {
  strings:
    $key_2f03 = { 7c 6c [2] 58 62 [2] 73 4e [2] 5d 6c [2] 49 77 [2] 46 6d [2] 58 70 [2] 5a 71 [2] 41 77 [2] 5d 70 [2] 41 5f }

  condition:
    any of them
}