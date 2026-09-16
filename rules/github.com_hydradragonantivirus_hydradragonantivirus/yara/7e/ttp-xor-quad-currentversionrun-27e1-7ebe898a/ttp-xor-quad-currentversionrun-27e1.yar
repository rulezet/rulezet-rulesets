rule TTP_XOR_QUAD_CurrentVersionRun_27e1 {
  strings:
    $key_27e1 = { 74 8e [2] 50 80 [2] 7b ac [2] 55 8e [2] 41 95 [2] 4e 8f [2] 50 92 [2] 52 93 [2] 49 95 [2] 55 92 [2] 49 bd }

  condition:
    any of them
}