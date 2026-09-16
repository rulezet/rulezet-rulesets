rule TTP_XOR_QUAD_CurrentVersionRun_5003 {
  strings:
    $key_5003 = { 03 6c [2] 27 62 [2] 0c 4e [2] 22 6c [2] 36 77 [2] 39 6d [2] 27 70 [2] 25 71 [2] 3e 77 [2] 22 70 [2] 3e 5f }

  condition:
    any of them
}