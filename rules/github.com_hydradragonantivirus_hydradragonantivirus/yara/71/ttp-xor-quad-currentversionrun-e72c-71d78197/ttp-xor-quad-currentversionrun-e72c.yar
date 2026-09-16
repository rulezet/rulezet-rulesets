rule TTP_XOR_QUAD_CurrentVersionRun_e72c {
  strings:
    $key_e72c = { b4 43 [2] 90 4d [2] bb 61 [2] 95 43 [2] 81 58 [2] 8e 42 [2] 90 5f [2] 92 5e [2] 89 58 [2] 95 5f [2] 89 70 }

  condition:
    any of them
}