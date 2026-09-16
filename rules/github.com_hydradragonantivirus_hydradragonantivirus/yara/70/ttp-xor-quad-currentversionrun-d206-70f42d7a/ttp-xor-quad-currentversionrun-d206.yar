rule TTP_XOR_QUAD_CurrentVersionRun_d206 {
  strings:
    $key_d206 = { 81 69 [2] a5 67 [2] 8e 4b [2] a0 69 [2] b4 72 [2] bb 68 [2] a5 75 [2] a7 74 [2] bc 72 [2] a0 75 [2] bc 5a }

  condition:
    any of them
}