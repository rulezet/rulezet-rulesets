rule TTP_XOR_QUAD_CurrentVersionRun_38e1 {
  strings:
    $key_38e1 = { 6b 8e [2] 4f 80 [2] 64 ac [2] 4a 8e [2] 5e 95 [2] 51 8f [2] 4f 92 [2] 4d 93 [2] 56 95 [2] 4a 92 [2] 56 bd }

  condition:
    any of them
}