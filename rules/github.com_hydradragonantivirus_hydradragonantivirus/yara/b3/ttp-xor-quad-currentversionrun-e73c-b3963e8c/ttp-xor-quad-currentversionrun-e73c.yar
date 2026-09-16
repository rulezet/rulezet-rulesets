rule TTP_XOR_QUAD_CurrentVersionRun_e73c {
  strings:
    $key_e73c = { b4 53 [2] 90 5d [2] bb 71 [2] 95 53 [2] 81 48 [2] 8e 52 [2] 90 4f [2] 92 4e [2] 89 48 [2] 95 4f [2] 89 60 }

  condition:
    any of them
}