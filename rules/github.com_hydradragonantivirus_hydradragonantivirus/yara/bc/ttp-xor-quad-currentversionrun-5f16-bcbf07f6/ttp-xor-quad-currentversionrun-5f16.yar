rule TTP_XOR_QUAD_CurrentVersionRun_5f16 {
  strings:
    $key_5f16 = { 0c 79 [2] 28 77 [2] 03 5b [2] 2d 79 [2] 39 62 [2] 36 78 [2] 28 65 [2] 2a 64 [2] 31 62 [2] 2d 65 [2] 31 4a }

  condition:
    any of them
}