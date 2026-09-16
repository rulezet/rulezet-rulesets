rule TTP_XOR_QUAD_CurrentVersionRun_f50b {
  strings:
    $key_f50b = { a6 64 [2] 82 6a [2] a9 46 [2] 87 64 [2] 93 7f [2] 9c 65 [2] 82 78 [2] 80 79 [2] 9b 7f [2] 87 78 [2] 9b 57 }

  condition:
    any of them
}