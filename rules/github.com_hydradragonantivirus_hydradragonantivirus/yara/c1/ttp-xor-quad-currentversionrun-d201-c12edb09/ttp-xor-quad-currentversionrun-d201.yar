rule TTP_XOR_QUAD_CurrentVersionRun_d201 {
  strings:
    $key_d201 = { 81 6e [2] a5 60 [2] 8e 4c [2] a0 6e [2] b4 75 [2] bb 6f [2] a5 72 [2] a7 73 [2] bc 75 [2] a0 72 [2] bc 5d }

  condition:
    any of them
}