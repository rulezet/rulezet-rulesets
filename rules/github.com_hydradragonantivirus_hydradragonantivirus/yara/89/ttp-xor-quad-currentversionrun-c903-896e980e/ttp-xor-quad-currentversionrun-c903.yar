rule TTP_XOR_QUAD_CurrentVersionRun_c903 {
  strings:
    $key_c903 = { 9a 6c [2] be 62 [2] 95 4e [2] bb 6c [2] af 77 [2] a0 6d [2] be 70 [2] bc 71 [2] a7 77 [2] bb 70 [2] a7 5f }

  condition:
    any of them
}