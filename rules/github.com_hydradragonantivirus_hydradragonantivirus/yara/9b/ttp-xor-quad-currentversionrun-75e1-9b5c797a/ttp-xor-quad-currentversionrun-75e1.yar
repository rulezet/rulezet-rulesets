rule TTP_XOR_QUAD_CurrentVersionRun_75e1 {
  strings:
    $key_75e1 = { 26 8e [2] 02 80 [2] 29 ac [2] 07 8e [2] 13 95 [2] 1c 8f [2] 02 92 [2] 00 93 [2] 1b 95 [2] 07 92 [2] 1b bd }

  condition:
    any of them
}