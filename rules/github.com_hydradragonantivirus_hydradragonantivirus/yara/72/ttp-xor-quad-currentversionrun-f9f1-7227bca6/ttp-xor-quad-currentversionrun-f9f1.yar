rule TTP_XOR_QUAD_CurrentVersionRun_f9f1 {
  strings:
    $key_f9f1 = { aa 9e [2] 8e 90 [2] a5 bc [2] 8b 9e [2] 9f 85 [2] 90 9f [2] 8e 82 [2] 8c 83 [2] 97 85 [2] 8b 82 [2] 97 ad }

  condition:
    any of them
}