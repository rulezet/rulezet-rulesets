rule TTP_XOR_QUAD_CurrentVersionRun_e71f {
  strings:
    $key_e71f = { b4 70 [2] 90 7e [2] bb 52 [2] 95 70 [2] 81 6b [2] 8e 71 [2] 90 6c [2] 92 6d [2] 89 6b [2] 95 6c [2] 89 43 }

  condition:
    any of them
}