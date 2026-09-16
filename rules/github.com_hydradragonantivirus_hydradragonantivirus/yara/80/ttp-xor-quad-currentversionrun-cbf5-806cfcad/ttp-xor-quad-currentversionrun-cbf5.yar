rule TTP_XOR_QUAD_CurrentVersionRun_cbf5 {
  strings:
    $key_cbf5 = { 98 9a [2] bc 94 [2] 97 b8 [2] b9 9a [2] ad 81 [2] a2 9b [2] bc 86 [2] be 87 [2] a5 81 [2] b9 86 [2] a5 a9 }

  condition:
    any of them
}