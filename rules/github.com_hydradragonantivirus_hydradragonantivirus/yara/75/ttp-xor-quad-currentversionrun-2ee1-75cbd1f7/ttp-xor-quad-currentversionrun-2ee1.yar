rule TTP_XOR_QUAD_CurrentVersionRun_2ee1 {
  strings:
    $key_2ee1 = { 7d 8e [2] 59 80 [2] 72 ac [2] 5c 8e [2] 48 95 [2] 47 8f [2] 59 92 [2] 5b 93 [2] 40 95 [2] 5c 92 [2] 40 bd }

  condition:
    any of them
}