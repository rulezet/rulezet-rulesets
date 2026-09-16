rule TTP_XOR_QUAD_CurrentVersionRun_da7b {
  strings:
    $key_da7b = { 89 14 [2] ad 1a [2] 86 36 [2] a8 14 [2] bc 0f [2] b3 15 [2] ad 08 [2] af 09 [2] b4 0f [2] a8 08 [2] b4 27 }

  condition:
    any of them
}