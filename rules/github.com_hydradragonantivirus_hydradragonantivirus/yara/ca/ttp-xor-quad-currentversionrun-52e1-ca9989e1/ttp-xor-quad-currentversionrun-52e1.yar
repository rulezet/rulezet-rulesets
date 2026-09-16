rule TTP_XOR_QUAD_CurrentVersionRun_52e1 {
  strings:
    $key_52e1 = { 01 8e [2] 25 80 [2] 0e ac [2] 20 8e [2] 34 95 [2] 3b 8f [2] 25 92 [2] 27 93 [2] 3c 95 [2] 20 92 [2] 3c bd }

  condition:
    any of them
}