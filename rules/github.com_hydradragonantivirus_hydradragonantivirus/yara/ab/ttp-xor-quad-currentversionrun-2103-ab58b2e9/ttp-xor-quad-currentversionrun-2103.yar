rule TTP_XOR_QUAD_CurrentVersionRun_2103 {
  strings:
    $key_2103 = { 72 6c [2] 56 62 [2] 7d 4e [2] 53 6c [2] 47 77 [2] 48 6d [2] 56 70 [2] 54 71 [2] 4f 77 [2] 53 70 [2] 4f 5f }

  condition:
    any of them
}