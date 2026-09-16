rule TTP_XOR_QUAD_CurrentVersionRun_da0a {
  strings:
    $key_da0a = { 89 65 [2] ad 6b [2] 86 47 [2] a8 65 [2] bc 7e [2] b3 64 [2] ad 79 [2] af 78 [2] b4 7e [2] a8 79 [2] b4 56 }

  condition:
    any of them
}