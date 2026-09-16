rule TTP_XOR_QUAD_CurrentVersionRun_f20b {
  strings:
    $key_f20b = { a1 64 [2] 85 6a [2] ae 46 [2] 80 64 [2] 94 7f [2] 9b 65 [2] 85 78 [2] 87 79 [2] 9c 7f [2] 80 78 [2] 9c 57 }

  condition:
    any of them
}