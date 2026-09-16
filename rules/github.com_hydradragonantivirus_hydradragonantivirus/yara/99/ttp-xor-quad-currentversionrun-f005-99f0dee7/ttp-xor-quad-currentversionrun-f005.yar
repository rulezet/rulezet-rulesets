rule TTP_XOR_QUAD_CurrentVersionRun_f005 {
  strings:
    $key_f005 = { a3 6a [2] 87 64 [2] ac 48 [2] 82 6a [2] 96 71 [2] 99 6b [2] 87 76 [2] 85 77 [2] 9e 71 [2] 82 76 [2] 9e 59 }

  condition:
    any of them
}