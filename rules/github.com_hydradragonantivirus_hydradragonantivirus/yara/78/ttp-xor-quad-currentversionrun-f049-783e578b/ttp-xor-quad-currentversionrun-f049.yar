rule TTP_XOR_QUAD_CurrentVersionRun_f049 {
  strings:
    $key_f049 = { a3 26 [2] 87 28 [2] ac 04 [2] 82 26 [2] 96 3d [2] 99 27 [2] 87 3a [2] 85 3b [2] 9e 3d [2] 82 3a [2] 9e 15 }

  condition:
    any of them
}