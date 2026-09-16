rule TTP_XOR_QUAD_CurrentVersionRun_e0dd {
  strings:
    $key_e0dd = { b3 b2 [2] 97 bc [2] bc 90 [2] 92 b2 [2] 86 a9 [2] 89 b3 [2] 97 ae [2] 95 af [2] 8e a9 [2] 92 ae [2] 8e 81 }

  condition:
    any of them
}