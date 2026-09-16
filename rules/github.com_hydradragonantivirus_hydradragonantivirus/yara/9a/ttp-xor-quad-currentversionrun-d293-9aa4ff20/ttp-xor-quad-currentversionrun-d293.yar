rule TTP_XOR_QUAD_CurrentVersionRun_d293 {
  strings:
    $key_d293 = { 81 fc [2] a5 f2 [2] 8e de [2] a0 fc [2] b4 e7 [2] bb fd [2] a5 e0 [2] a7 e1 [2] bc e7 [2] a0 e0 [2] bc cf }

  condition:
    any of them
}