rule TTP_XOR_QUAD_CurrentVersionRun_d516 {
  strings:
    $key_d516 = { 86 79 [2] a2 77 [2] 89 5b [2] a7 79 [2] b3 62 [2] bc 78 [2] a2 65 [2] a0 64 [2] bb 62 [2] a7 65 [2] bb 4a }

  condition:
    any of them
}