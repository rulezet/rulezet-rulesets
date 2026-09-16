rule TTP_XOR_QUAD_CurrentVersionRun_da26 {
  strings:
    $key_da26 = { 89 49 [2] ad 47 [2] 86 6b [2] a8 49 [2] bc 52 [2] b3 48 [2] ad 55 [2] af 54 [2] b4 52 [2] a8 55 [2] b4 7a }

  condition:
    any of them
}