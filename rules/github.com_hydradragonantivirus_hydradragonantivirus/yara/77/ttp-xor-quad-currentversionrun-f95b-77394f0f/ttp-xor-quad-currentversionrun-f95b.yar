rule TTP_XOR_QUAD_CurrentVersionRun_f95b {
  strings:
    $key_f95b = { aa 34 [2] 8e 3a [2] a5 16 [2] 8b 34 [2] 9f 2f [2] 90 35 [2] 8e 28 [2] 8c 29 [2] 97 2f [2] 8b 28 [2] 97 07 }

  condition:
    any of them
}