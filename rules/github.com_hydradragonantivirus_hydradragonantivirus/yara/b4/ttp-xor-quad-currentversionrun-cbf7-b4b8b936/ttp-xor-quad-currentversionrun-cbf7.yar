rule TTP_XOR_QUAD_CurrentVersionRun_cbf7 {
  strings:
    $key_cbf7 = { 98 98 [2] bc 96 [2] 97 ba [2] b9 98 [2] ad 83 [2] a2 99 [2] bc 84 [2] be 85 [2] a5 83 [2] b9 84 [2] a5 ab }

  condition:
    any of them
}