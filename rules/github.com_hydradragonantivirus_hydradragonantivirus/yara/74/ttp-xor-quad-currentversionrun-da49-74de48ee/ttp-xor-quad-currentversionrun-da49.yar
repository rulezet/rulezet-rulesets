rule TTP_XOR_QUAD_CurrentVersionRun_da49 {
  strings:
    $key_da49 = { 89 26 [2] ad 28 [2] 86 04 [2] a8 26 [2] bc 3d [2] b3 27 [2] ad 3a [2] af 3b [2] b4 3d [2] a8 3a [2] b4 15 }

  condition:
    any of them
}