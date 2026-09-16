rule TTP_XOR_QUAD_CurrentVersionRun_f26d {
  strings:
    $key_f26d = { a1 02 [2] 85 0c [2] ae 20 [2] 80 02 [2] 94 19 [2] 9b 03 [2] 85 1e [2] 87 1f [2] 9c 19 [2] 80 1e [2] 9c 31 }

  condition:
    any of them
}