rule TTP_XOR_QUAD_CurrentVersionRun_6de1 {
  strings:
    $key_6de1 = { 3e 8e [2] 1a 80 [2] 31 ac [2] 1f 8e [2] 0b 95 [2] 04 8f [2] 1a 92 [2] 18 93 [2] 03 95 [2] 1f 92 [2] 03 bd }

  condition:
    any of them
}