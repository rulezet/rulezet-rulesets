rule TTP_XOR_QUAD_CurrentVersionRun_f27f {
  strings:
    $key_f27f = { a1 10 [2] 85 1e [2] ae 32 [2] 80 10 [2] 94 0b [2] 9b 11 [2] 85 0c [2] 87 0d [2] 9c 0b [2] 80 0c [2] 9c 23 }

  condition:
    any of them
}