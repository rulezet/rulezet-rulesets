rule TTP_XOR_QUAD_CurrentVersionRun_cbe0 {
  strings:
    $key_cbe0 = { 98 8f [2] bc 81 [2] 97 ad [2] b9 8f [2] ad 94 [2] a2 8e [2] bc 93 [2] be 92 [2] a5 94 [2] b9 93 [2] a5 bc }

  condition:
    any of them
}