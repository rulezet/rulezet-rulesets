rule TTP_XOR_QUAD_CurrentVersionRun_2003 {
  strings:
    $key_2003 = { 73 6c [2] 57 62 [2] 7c 4e [2] 52 6c [2] 46 77 [2] 49 6d [2] 57 70 [2] 55 71 [2] 4e 77 [2] 52 70 [2] 4e 5f }

  condition:
    any of them
}