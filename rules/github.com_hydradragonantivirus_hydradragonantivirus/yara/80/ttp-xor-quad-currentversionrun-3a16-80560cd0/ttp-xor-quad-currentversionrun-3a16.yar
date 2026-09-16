rule TTP_XOR_QUAD_CurrentVersionRun_3a16 {
  strings:
    $key_3a16 = { 69 79 [2] 4d 77 [2] 66 5b [2] 48 79 [2] 5c 62 [2] 53 78 [2] 4d 65 [2] 4f 64 [2] 54 62 [2] 48 65 [2] 54 4a }

  condition:
    any of them
}