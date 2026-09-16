rule TTP_XOR_QUAD_CurrentVersionRun_7e16 {
  strings:
    $key_7e16 = { 2d 79 [2] 09 77 [2] 22 5b [2] 0c 79 [2] 18 62 [2] 17 78 [2] 09 65 [2] 0b 64 [2] 10 62 [2] 0c 65 [2] 10 4a }

  condition:
    any of them
}