rule TTP_XOR_QUAD_CurrentVersionRun_0ee1 {
  strings:
    $key_0ee1 = { 5d 8e [2] 79 80 [2] 52 ac [2] 7c 8e [2] 68 95 [2] 67 8f [2] 79 92 [2] 7b 93 [2] 60 95 [2] 7c 92 [2] 60 bd }

  condition:
    any of them
}