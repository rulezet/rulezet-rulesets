rule TTP_XOR_QUAD_CurrentVersionRun_3903 {
  strings:
    $key_3903 = { 6a 6c [2] 4e 62 [2] 65 4e [2] 4b 6c [2] 5f 77 [2] 50 6d [2] 4e 70 [2] 4c 71 [2] 57 77 [2] 4b 70 [2] 57 5f }

  condition:
    any of them
}