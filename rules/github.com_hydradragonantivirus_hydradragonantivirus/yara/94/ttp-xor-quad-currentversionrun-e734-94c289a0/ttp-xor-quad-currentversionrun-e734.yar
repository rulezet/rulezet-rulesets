rule TTP_XOR_QUAD_CurrentVersionRun_e734 {
  strings:
    $key_e734 = { b4 5b [2] 90 55 [2] bb 79 [2] 95 5b [2] 81 40 [2] 8e 5a [2] 90 47 [2] 92 46 [2] 89 40 [2] 95 47 [2] 89 68 }

  condition:
    any of them
}