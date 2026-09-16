rule TTP_XOR_QUAD_CurrentVersionRun_32e1 {
  strings:
    $key_32e1 = { 61 8e [2] 45 80 [2] 6e ac [2] 40 8e [2] 54 95 [2] 5b 8f [2] 45 92 [2] 47 93 [2] 5c 95 [2] 40 92 [2] 5c bd }

  condition:
    any of them
}