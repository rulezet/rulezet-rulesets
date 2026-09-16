rule TTP_XOR_QUAD_CurrentVersionRun_d231 {
  strings:
    $key_d231 = { 81 5e [2] a5 50 [2] 8e 7c [2] a0 5e [2] b4 45 [2] bb 5f [2] a5 42 [2] a7 43 [2] bc 45 [2] a0 42 [2] bc 6d }

  condition:
    any of them
}