rule TTP_XOR_QUAD_CurrentVersionRun_1903 {
  strings:
    $key_1903 = { 4a 6c [2] 6e 62 [2] 45 4e [2] 6b 6c [2] 7f 77 [2] 70 6d [2] 6e 70 [2] 6c 71 [2] 77 77 [2] 6b 70 [2] 77 5f }

  condition:
    any of them
}