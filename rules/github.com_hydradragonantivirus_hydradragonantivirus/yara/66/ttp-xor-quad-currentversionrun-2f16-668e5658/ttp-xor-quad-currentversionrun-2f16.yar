rule TTP_XOR_QUAD_CurrentVersionRun_2f16 {
  strings:
    $key_2f16 = { 7c 79 [2] 58 77 [2] 73 5b [2] 5d 79 [2] 49 62 [2] 46 78 [2] 58 65 [2] 5a 64 [2] 41 62 [2] 5d 65 [2] 41 4a }

  condition:
    any of them
}