rule TTP_XOR_QUAD_CurrentVersionRun_0903 {
  strings:
    $key_0903 = { 5a 6c [2] 7e 62 [2] 55 4e [2] 7b 6c [2] 6f 77 [2] 60 6d [2] 7e 70 [2] 7c 71 [2] 67 77 [2] 7b 70 [2] 67 5f }

  condition:
    any of them
}