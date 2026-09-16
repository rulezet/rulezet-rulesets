rule TTP_XOR_QUAD_CurrentVersionRun_6203 {
  strings:
    $key_6203 = { 31 6c [2] 15 62 [2] 3e 4e [2] 10 6c [2] 04 77 [2] 0b 6d [2] 15 70 [2] 17 71 [2] 0c 77 [2] 10 70 [2] 0c 5f }

  condition:
    any of them
}