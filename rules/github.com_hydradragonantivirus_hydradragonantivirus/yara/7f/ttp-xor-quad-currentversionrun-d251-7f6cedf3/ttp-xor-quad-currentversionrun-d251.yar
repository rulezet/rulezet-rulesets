rule TTP_XOR_QUAD_CurrentVersionRun_d251 {
  strings:
    $key_d251 = { 81 3e [2] a5 30 [2] 8e 1c [2] a0 3e [2] b4 25 [2] bb 3f [2] a5 22 [2] a7 23 [2] bc 25 [2] a0 22 [2] bc 0d }

  condition:
    any of them
}