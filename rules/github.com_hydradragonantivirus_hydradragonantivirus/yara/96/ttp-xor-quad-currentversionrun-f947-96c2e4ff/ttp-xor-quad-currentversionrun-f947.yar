rule TTP_XOR_QUAD_CurrentVersionRun_f947 {
  strings:
    $key_f947 = { aa 28 [2] 8e 26 [2] a5 0a [2] 8b 28 [2] 9f 33 [2] 90 29 [2] 8e 34 [2] 8c 35 [2] 97 33 [2] 8b 34 [2] 97 1b }

  condition:
    any of them
}