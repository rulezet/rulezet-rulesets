rule TTP_XOR_QUAD_CurrentVersionRun_ebe1 {
  strings:
    $key_ebe1 = { b8 8e [2] 9c 80 [2] b7 ac [2] 99 8e [2] 8d 95 [2] 82 8f [2] 9c 92 [2] 9e 93 [2] 85 95 [2] 99 92 [2] 85 bd }

  condition:
    any of them
}