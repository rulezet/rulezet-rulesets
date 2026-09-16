rule TTP_XOR_QUAD_CurrentVersionRun_e72a {
  strings:
    $key_e72a = { b4 45 [2] 90 4b [2] bb 67 [2] 95 45 [2] 81 5e [2] 8e 44 [2] 90 59 [2] 92 58 [2] 89 5e [2] 95 59 [2] 89 76 }

  condition:
    any of them
}