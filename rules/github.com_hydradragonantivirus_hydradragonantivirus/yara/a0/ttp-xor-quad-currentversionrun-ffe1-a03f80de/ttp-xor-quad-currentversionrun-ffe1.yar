rule TTP_XOR_QUAD_CurrentVersionRun_ffe1 {
  strings:
    $key_ffe1 = { ac 8e [2] 88 80 [2] a3 ac [2] 8d 8e [2] 99 95 [2] 96 8f [2] 88 92 [2] 8a 93 [2] 91 95 [2] 8d 92 [2] 91 bd }

  condition:
    any of them
}