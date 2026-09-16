rule TTP_XOR_QUAD_CurrentVersionRun_0f16 {
  strings:
    $key_0f16 = { 5c 79 [2] 78 77 [2] 53 5b [2] 7d 79 [2] 69 62 [2] 66 78 [2] 78 65 [2] 7a 64 [2] 61 62 [2] 7d 65 [2] 61 4a }

  condition:
    any of them
}