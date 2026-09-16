rule TTP_XOR_QUAD_CurrentVersionRun_f019 {
  strings:
    $key_f019 = { a3 76 [2] 87 78 [2] ac 54 [2] 82 76 [2] 96 6d [2] 99 77 [2] 87 6a [2] 85 6b [2] 9e 6d [2] 82 6a [2] 9e 45 }

  condition:
    any of them
}