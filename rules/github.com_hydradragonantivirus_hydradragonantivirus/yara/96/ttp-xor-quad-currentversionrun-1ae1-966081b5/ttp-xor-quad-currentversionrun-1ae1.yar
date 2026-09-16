rule TTP_XOR_QUAD_CurrentVersionRun_1ae1 {
  strings:
    $key_1ae1 = { 49 8e [2] 6d 80 [2] 46 ac [2] 68 8e [2] 7c 95 [2] 73 8f [2] 6d 92 [2] 6f 93 [2] 74 95 [2] 68 92 [2] 74 bd }

  condition:
    any of them
}