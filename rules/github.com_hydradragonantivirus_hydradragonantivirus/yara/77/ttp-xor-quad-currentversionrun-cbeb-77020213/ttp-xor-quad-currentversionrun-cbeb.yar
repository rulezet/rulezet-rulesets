rule TTP_XOR_QUAD_CurrentVersionRun_cbeb {
  strings:
    $key_cbeb = { 98 84 [2] bc 8a [2] 97 a6 [2] b9 84 [2] ad 9f [2] a2 85 [2] bc 98 [2] be 99 [2] a5 9f [2] b9 98 [2] a5 b7 }

  condition:
    any of them
}