rule TTP_XOR_QUAD_CurrentVersionRun_1a03 {
  strings:
    $key_1a03 = { 49 6c [2] 6d 62 [2] 46 4e [2] 68 6c [2] 7c 77 [2] 73 6d [2] 6d 70 [2] 6f 71 [2] 74 77 [2] 68 70 [2] 74 5f }

  condition:
    any of them
}