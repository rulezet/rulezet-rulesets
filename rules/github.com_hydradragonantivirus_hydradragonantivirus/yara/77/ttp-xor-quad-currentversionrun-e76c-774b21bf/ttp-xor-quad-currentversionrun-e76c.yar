rule TTP_XOR_QUAD_CurrentVersionRun_e76c {
  strings:
    $key_e76c = { b4 03 [2] 90 0d [2] bb 21 [2] 95 03 [2] 81 18 [2] 8e 02 [2] 90 1f [2] 92 1e [2] 89 18 [2] 95 1f [2] 89 30 }

  condition:
    any of them
}