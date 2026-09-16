rule TTP_XOR_QUAD_CurrentVersionRun_fee1 {
  strings:
    $key_fee1 = { ad 8e [2] 89 80 [2] a2 ac [2] 8c 8e [2] 98 95 [2] 97 8f [2] 89 92 [2] 8b 93 [2] 90 95 [2] 8c 92 [2] 90 bd }

  condition:
    any of them
}