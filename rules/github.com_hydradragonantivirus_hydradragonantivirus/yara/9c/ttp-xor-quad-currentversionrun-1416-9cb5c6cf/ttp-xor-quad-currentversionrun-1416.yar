rule TTP_XOR_QUAD_CurrentVersionRun_1416 {
  strings:
    $key_1416 = { 47 79 [2] 63 77 [2] 48 5b [2] 66 79 [2] 72 62 [2] 7d 78 [2] 63 65 [2] 61 64 [2] 7a 62 [2] 66 65 [2] 7a 4a }

  condition:
    any of them
}