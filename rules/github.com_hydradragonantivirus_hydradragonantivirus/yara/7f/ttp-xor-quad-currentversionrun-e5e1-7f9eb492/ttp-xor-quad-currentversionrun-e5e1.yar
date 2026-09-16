rule TTP_XOR_QUAD_CurrentVersionRun_e5e1 {
  strings:
    $key_e5e1 = { b6 8e [2] 92 80 [2] b9 ac [2] 97 8e [2] 83 95 [2] 8c 8f [2] 92 92 [2] 90 93 [2] 8b 95 [2] 97 92 [2] 8b bd }

  condition:
    any of them
}