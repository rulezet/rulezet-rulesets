rule TTP_XOR_QUAD_CurrentVersionRun_f069 {
  strings:
    $key_f069 = { a3 06 [2] 87 08 [2] ac 24 [2] 82 06 [2] 96 1d [2] 99 07 [2] 87 1a [2] 85 1b [2] 9e 1d [2] 82 1a [2] 9e 35 }

  condition:
    any of them
}