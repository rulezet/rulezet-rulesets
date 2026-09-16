rule TTP_XOR_QUAD_CurrentVersionRun_f044 {
  strings:
    $key_f044 = { a3 2b [2] 87 25 [2] ac 09 [2] 82 2b [2] 96 30 [2] 99 2a [2] 87 37 [2] 85 36 [2] 9e 30 [2] 82 37 [2] 9e 18 }

  condition:
    any of them
}