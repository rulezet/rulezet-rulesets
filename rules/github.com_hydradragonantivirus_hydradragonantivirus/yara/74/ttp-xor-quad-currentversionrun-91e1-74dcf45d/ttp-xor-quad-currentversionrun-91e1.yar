rule TTP_XOR_QUAD_CurrentVersionRun_91e1 {
  strings:
    $key_91e1 = { c2 8e [2] e6 80 [2] cd ac [2] e3 8e [2] f7 95 [2] f8 8f [2] e6 92 [2] e4 93 [2] ff 95 [2] e3 92 [2] ff bd }

  condition:
    any of them
}