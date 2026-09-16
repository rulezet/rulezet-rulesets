rule TTP_XOR_QUAD_CurrentVersionRun_095b {
  strings:
    $key_095b = { 5a 34 [2] 7e 3a [2] 55 16 [2] 7b 34 [2] 6f 2f [2] 60 35 [2] 7e 28 [2] 7c 29 [2] 67 2f [2] 7b 28 [2] 67 07 }

  condition:
    any of them
}