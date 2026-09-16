rule TTP_XOR_QUAD_CurrentVersionRun_da1a {
  strings:
    $key_da1a = { 89 75 [2] ad 7b [2] 86 57 [2] a8 75 [2] bc 6e [2] b3 74 [2] ad 69 [2] af 68 [2] b4 6e [2] a8 69 [2] b4 46 }

  condition:
    any of them
}