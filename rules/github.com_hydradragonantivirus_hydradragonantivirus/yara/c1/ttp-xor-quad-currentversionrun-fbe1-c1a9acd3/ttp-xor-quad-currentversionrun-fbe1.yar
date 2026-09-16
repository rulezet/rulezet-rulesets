rule TTP_XOR_QUAD_CurrentVersionRun_fbe1 {
  strings:
    $key_fbe1 = { a8 8e [2] 8c 80 [2] a7 ac [2] 89 8e [2] 9d 95 [2] 92 8f [2] 8c 92 [2] 8e 93 [2] 95 95 [2] 89 92 [2] 95 bd }

  condition:
    any of them
}