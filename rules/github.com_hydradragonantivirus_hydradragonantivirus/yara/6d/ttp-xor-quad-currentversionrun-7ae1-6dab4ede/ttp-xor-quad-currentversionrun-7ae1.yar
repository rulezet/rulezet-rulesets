rule TTP_XOR_QUAD_CurrentVersionRun_7ae1 {
  strings:
    $key_7ae1 = { 29 8e [2] 0d 80 [2] 26 ac [2] 08 8e [2] 1c 95 [2] 13 8f [2] 0d 92 [2] 0f 93 [2] 14 95 [2] 08 92 [2] 14 bd }

  condition:
    any of them
}