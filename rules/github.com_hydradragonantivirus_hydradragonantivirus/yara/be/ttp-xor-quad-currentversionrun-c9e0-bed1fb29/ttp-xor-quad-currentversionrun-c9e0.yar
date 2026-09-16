rule TTP_XOR_QUAD_CurrentVersionRun_c9e0 {
  strings:
    $key_c9e0 = { 9a 8f [2] be 81 [2] 95 ad [2] bb 8f [2] af 94 [2] a0 8e [2] be 93 [2] bc 92 [2] a7 94 [2] bb 93 [2] a7 bc }

  condition:
    any of them
}