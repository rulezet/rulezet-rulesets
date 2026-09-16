rule TTP_XOR_QUAD_CurrentVersionRun_5ae1 {
  strings:
    $key_5ae1 = { 09 8e [2] 2d 80 [2] 06 ac [2] 28 8e [2] 3c 95 [2] 33 8f [2] 2d 92 [2] 2f 93 [2] 34 95 [2] 28 92 [2] 34 bd }

  condition:
    any of them
}