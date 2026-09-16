rule TTP_XOR_QUAD_CurrentVersionRun_d506 {
  strings:
    $key_d506 = { 86 69 [2] a2 67 [2] 89 4b [2] a7 69 [2] b3 72 [2] bc 68 [2] a2 75 [2] a0 74 [2] bb 72 [2] a7 75 [2] bb 5a }

  condition:
    any of them
}