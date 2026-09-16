rule TTP_XOR_QUAD_CurrentVersionRun_4f16 {
  strings:
    $key_4f16 = { 1c 79 [2] 38 77 [2] 13 5b [2] 3d 79 [2] 29 62 [2] 26 78 [2] 38 65 [2] 3a 64 [2] 21 62 [2] 3d 65 [2] 21 4a }

  condition:
    any of them
}