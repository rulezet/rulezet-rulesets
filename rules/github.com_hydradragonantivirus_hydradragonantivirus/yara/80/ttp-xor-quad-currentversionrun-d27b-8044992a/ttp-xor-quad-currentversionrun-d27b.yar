rule TTP_XOR_QUAD_CurrentVersionRun_d27b {
  strings:
    $key_d27b = { 81 14 [2] a5 1a [2] 8e 36 [2] a0 14 [2] b4 0f [2] bb 15 [2] a5 08 [2] a7 09 [2] bc 0f [2] a0 08 [2] bc 27 }

  condition:
    any of them
}