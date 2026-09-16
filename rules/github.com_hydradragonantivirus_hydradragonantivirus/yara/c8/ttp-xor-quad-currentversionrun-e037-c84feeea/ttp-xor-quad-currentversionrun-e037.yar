rule TTP_XOR_QUAD_CurrentVersionRun_e037 {
  strings:
    $key_e037 = { b3 58 [2] 97 56 [2] bc 7a [2] 92 58 [2] 86 43 [2] 89 59 [2] 97 44 [2] 95 45 [2] 8e 43 [2] 92 44 [2] 8e 6b }

  condition:
    any of them
}