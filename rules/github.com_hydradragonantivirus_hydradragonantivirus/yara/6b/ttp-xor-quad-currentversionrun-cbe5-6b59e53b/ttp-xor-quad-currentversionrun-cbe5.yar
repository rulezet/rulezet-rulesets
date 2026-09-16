rule TTP_XOR_QUAD_CurrentVersionRun_cbe5 {
  strings:
    $key_cbe5 = { 98 8a [2] bc 84 [2] 97 a8 [2] b9 8a [2] ad 91 [2] a2 8b [2] bc 96 [2] be 97 [2] a5 91 [2] b9 96 [2] a5 b9 }

  condition:
    any of them
}