rule TTP_XOR_QUAD_CurrentVersionRun_cba7 {
  strings:
    $key_cba7 = { 98 c8 [2] bc c6 [2] 97 ea [2] b9 c8 [2] ad d3 [2] a2 c9 [2] bc d4 [2] be d5 [2] a5 d3 [2] b9 d4 [2] a5 fb }

  condition:
    any of them
}