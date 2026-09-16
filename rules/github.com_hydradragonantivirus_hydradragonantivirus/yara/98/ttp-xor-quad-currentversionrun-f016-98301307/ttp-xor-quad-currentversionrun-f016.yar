rule TTP_XOR_QUAD_CurrentVersionRun_f016 {
  strings:
    $key_f016 = { a3 79 [2] 87 77 [2] ac 5b [2] 82 79 [2] 96 62 [2] 99 78 [2] 87 65 [2] 85 64 [2] 9e 62 [2] 82 65 [2] 9e 4a }

  condition:
    any of them
}