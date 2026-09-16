rule TTP_XOR_QUAD_CurrentVersionRun_e77c {
  strings:
    $key_e77c = { b4 13 [2] 90 1d [2] bb 31 [2] 95 13 [2] 81 08 [2] 8e 12 [2] 90 0f [2] 92 0e [2] 89 08 [2] 95 0f [2] 89 20 }

  condition:
    any of them
}