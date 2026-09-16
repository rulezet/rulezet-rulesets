rule TTP_XOR_QUAD_CurrentVersionRun_0ae1 {
  strings:
    $key_0ae1 = { 59 8e [2] 7d 80 [2] 56 ac [2] 78 8e [2] 6c 95 [2] 63 8f [2] 7d 92 [2] 7f 93 [2] 64 95 [2] 78 92 [2] 64 bd }

  condition:
    any of them
}