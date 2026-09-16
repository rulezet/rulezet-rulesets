rule TTP_XOR_QUAD_CurrentVersionRun_e72d {
  strings:
    $key_e72d = { b4 42 [2] 90 4c [2] bb 60 [2] 95 42 [2] 81 59 [2] 8e 43 [2] 90 5e [2] 92 5f [2] 89 59 [2] 95 5e [2] 89 71 }

  condition:
    any of them
}