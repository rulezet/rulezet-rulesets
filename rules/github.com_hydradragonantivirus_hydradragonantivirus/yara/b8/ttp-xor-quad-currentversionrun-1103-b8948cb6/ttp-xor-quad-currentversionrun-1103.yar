rule TTP_XOR_QUAD_CurrentVersionRun_1103 {
  strings:
    $key_1103 = { 42 6c [2] 66 62 [2] 4d 4e [2] 63 6c [2] 77 77 [2] 78 6d [2] 66 70 [2] 64 71 [2] 7f 77 [2] 63 70 [2] 7f 5f }

  condition:
    any of them
}