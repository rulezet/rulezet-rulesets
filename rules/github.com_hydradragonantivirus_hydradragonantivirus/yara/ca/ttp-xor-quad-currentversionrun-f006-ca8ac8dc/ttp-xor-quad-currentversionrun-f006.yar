rule TTP_XOR_QUAD_CurrentVersionRun_f006 {
  strings:
    $key_f006 = { a3 69 [2] 87 67 [2] ac 4b [2] 82 69 [2] 96 72 [2] 99 68 [2] 87 75 [2] 85 74 [2] 9e 72 [2] 82 75 [2] 9e 5a }

  condition:
    any of them
}