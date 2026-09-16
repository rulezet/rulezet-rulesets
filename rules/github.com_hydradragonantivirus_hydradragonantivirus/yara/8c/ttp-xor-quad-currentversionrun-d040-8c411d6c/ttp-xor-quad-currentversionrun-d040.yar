rule TTP_XOR_QUAD_CurrentVersionRun_d040 {
  strings:
    $key_d040 = { 83 2f [2] a7 21 [2] 8c 0d [2] a2 2f [2] b6 34 [2] b9 2e [2] a7 33 [2] a5 32 [2] be 34 [2] a2 33 [2] be 1c }

  condition:
    any of them
}