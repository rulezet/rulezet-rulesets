rule TTP_XOR_QUAD_CurrentVersionRun_e77e {
  strings:
    $key_e77e = { b4 11 [2] 90 1f [2] bb 33 [2] 95 11 [2] 81 0a [2] 8e 10 [2] 90 0d [2] 92 0c [2] 89 0a [2] 95 0d [2] 89 22 }

  condition:
    any of them
}