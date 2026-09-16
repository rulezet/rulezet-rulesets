rule TTP_XOR_QUAD_CurrentVersionRun_fa16 {
  strings:
    $key_fa16 = { a9 79 [2] 8d 77 [2] a6 5b [2] 88 79 [2] 9c 62 [2] 93 78 [2] 8d 65 [2] 8f 64 [2] 94 62 [2] 88 65 [2] 94 4a }

  condition:
    any of them
}