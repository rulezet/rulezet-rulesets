rule TTP_XOR_QUAD_CurrentVersionRun_e70a {
  strings:
    $key_e70a = { b4 65 [2] 90 6b [2] bb 47 [2] 95 65 [2] 81 7e [2] 8e 64 [2] 90 79 [2] 92 78 [2] 89 7e [2] 95 79 [2] 89 56 }

  condition:
    any of them
}