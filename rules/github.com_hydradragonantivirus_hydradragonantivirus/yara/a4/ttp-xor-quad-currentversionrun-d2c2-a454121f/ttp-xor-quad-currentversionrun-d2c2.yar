rule TTP_XOR_QUAD_CurrentVersionRun_d2c2 {
  strings:
    $key_d2c2 = { 81 ad [2] a5 a3 [2] 8e 8f [2] a0 ad [2] b4 b6 [2] bb ac [2] a5 b1 [2] a7 b0 [2] bc b6 [2] a0 b1 [2] bc 9e }

  condition:
    any of them
}