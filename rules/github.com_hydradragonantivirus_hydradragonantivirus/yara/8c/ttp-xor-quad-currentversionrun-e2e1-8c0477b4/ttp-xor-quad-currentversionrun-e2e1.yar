rule TTP_XOR_QUAD_CurrentVersionRun_e2e1 {
  strings:
    $key_e2e1 = { b1 8e [2] 95 80 [2] be ac [2] 90 8e [2] 84 95 [2] 8b 8f [2] 95 92 [2] 97 93 [2] 8c 95 [2] 90 92 [2] 8c bd }

  condition:
    any of them
}