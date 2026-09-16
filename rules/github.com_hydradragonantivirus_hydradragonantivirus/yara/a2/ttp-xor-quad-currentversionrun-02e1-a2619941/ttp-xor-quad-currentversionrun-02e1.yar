rule TTP_XOR_QUAD_CurrentVersionRun_02e1 {
  strings:
    $key_02e1 = { 51 8e [2] 75 80 [2] 5e ac [2] 70 8e [2] 64 95 [2] 6b 8f [2] 75 92 [2] 77 93 [2] 6c 95 [2] 70 92 [2] 6c bd }

  condition:
    any of them
}