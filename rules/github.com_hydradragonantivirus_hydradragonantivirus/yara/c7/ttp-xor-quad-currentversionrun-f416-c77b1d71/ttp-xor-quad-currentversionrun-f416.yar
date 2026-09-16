rule TTP_XOR_QUAD_CurrentVersionRun_f416 {
  strings:
    $key_f416 = { a7 79 [2] 83 77 [2] a8 5b [2] 86 79 [2] 92 62 [2] 9d 78 [2] 83 65 [2] 81 64 [2] 9a 62 [2] 86 65 [2] 9a 4a }

  condition:
    any of them
}