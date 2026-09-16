rule TTP_XOR_QUAD_CurrentVersionRun_55e1 {
  strings:
    $key_55e1 = { 06 8e [2] 22 80 [2] 09 ac [2] 27 8e [2] 33 95 [2] 3c 8f [2] 22 92 [2] 20 93 [2] 3b 95 [2] 27 92 [2] 3b bd }

  condition:
    any of them
}