rule TTP_XOR_QUAD_CurrentVersionRun_5816 {
  strings:
    $key_5816 = { 0b 79 [2] 2f 77 [2] 04 5b [2] 2a 79 [2] 3e 62 [2] 31 78 [2] 2f 65 [2] 2d 64 [2] 36 62 [2] 2a 65 [2] 36 4a }

  condition:
    any of them
}