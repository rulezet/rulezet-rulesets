rule TTP_XOR_QUAD_CurrentVersionRun_da2b {
  strings:
    $key_da2b = { 89 44 [2] ad 4a [2] 86 66 [2] a8 44 [2] bc 5f [2] b3 45 [2] ad 58 [2] af 59 [2] b4 5f [2] a8 58 [2] b4 77 }

  condition:
    any of them
}