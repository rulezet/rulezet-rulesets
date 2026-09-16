rule TTP_XOR_QUAD_CurrentVersionRun_e77d {
  strings:
    $key_e77d = { b4 12 [2] 90 1c [2] bb 30 [2] 95 12 [2] 81 09 [2] 8e 13 [2] 90 0e [2] 92 0f [2] 89 09 [2] 95 0e [2] 89 21 }

  condition:
    any of them
}