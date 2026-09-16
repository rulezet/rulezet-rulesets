rule TTP_XOR_QUAD_CurrentVersionRun_e70f {
  strings:
    $key_e70f = { b4 60 [2] 90 6e [2] bb 42 [2] 95 60 [2] 81 7b [2] 8e 61 [2] 90 7c [2] 92 7d [2] 89 7b [2] 95 7c [2] 89 53 }

  condition:
    any of them
}