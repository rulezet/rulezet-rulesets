rule TTP_XOR_QUAD_CurrentVersionRun_2a16 {
  strings:
    $key_2a16 = { 79 79 [2] 5d 77 [2] 76 5b [2] 58 79 [2] 4c 62 [2] 43 78 [2] 5d 65 [2] 5f 64 [2] 44 62 [2] 58 65 [2] 44 4a }

  condition:
    any of them
}