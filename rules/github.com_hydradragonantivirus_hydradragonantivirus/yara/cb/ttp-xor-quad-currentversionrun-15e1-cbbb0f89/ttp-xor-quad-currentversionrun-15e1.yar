rule TTP_XOR_QUAD_CurrentVersionRun_15e1 {
  strings:
    $key_15e1 = { 46 8e [2] 62 80 [2] 49 ac [2] 67 8e [2] 73 95 [2] 7c 8f [2] 62 92 [2] 60 93 [2] 7b 95 [2] 67 92 [2] 7b bd }

  condition:
    any of them
}