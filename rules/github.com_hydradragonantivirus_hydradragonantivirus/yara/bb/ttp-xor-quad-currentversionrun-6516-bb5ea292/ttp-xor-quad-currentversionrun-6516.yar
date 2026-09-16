rule TTP_XOR_QUAD_CurrentVersionRun_6516 {
  strings:
    $key_6516 = { 36 79 [2] 12 77 [2] 39 5b [2] 17 79 [2] 03 62 [2] 0c 78 [2] 12 65 [2] 10 64 [2] 0b 62 [2] 17 65 [2] 0b 4a }

  condition:
    any of them
}