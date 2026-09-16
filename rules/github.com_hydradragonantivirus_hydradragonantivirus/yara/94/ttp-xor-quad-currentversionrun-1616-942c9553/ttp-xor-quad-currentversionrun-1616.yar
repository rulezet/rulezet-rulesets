rule TTP_XOR_QUAD_CurrentVersionRun_1616 {
  strings:
    $key_1616 = { 45 79 [2] 61 77 [2] 4a 5b [2] 64 79 [2] 70 62 [2] 7f 78 [2] 61 65 [2] 63 64 [2] 78 62 [2] 64 65 [2] 78 4a }

  condition:
    any of them
}