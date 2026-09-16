rule TTP_XOR_QUAD_CurrentVersionRun_daeb {
  strings:
    $key_daeb = { 89 84 [2] ad 8a [2] 86 a6 [2] a8 84 [2] bc 9f [2] b3 85 [2] ad 98 [2] af 99 [2] b4 9f [2] a8 98 [2] b4 b7 }

  condition:
    any of them
}