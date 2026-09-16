rule TTP_XOR_QUAD_CurrentVersionRun_e4e1 {
  strings:
    $key_e4e1 = { b7 8e [2] 93 80 [2] b8 ac [2] 96 8e [2] 82 95 [2] 8d 8f [2] 93 92 [2] 91 93 [2] 8a 95 [2] 96 92 [2] 8a bd }

  condition:
    any of them
}