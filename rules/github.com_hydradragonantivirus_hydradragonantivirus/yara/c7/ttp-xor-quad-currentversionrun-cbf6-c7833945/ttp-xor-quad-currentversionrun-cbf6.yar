rule TTP_XOR_QUAD_CurrentVersionRun_cbf6 {
  strings:
    $key_cbf6 = { 98 99 [2] bc 97 [2] 97 bb [2] b9 99 [2] ad 82 [2] a2 98 [2] bc 85 [2] be 84 [2] a5 82 [2] b9 85 [2] a5 aa }

  condition:
    any of them
}