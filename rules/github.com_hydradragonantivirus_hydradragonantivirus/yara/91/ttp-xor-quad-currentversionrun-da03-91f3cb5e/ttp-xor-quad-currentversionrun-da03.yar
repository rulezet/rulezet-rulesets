rule TTP_XOR_QUAD_CurrentVersionRun_da03 {
  strings:
    $key_da03 = { 89 6c [2] ad 62 [2] 86 4e [2] a8 6c [2] bc 77 [2] b3 6d [2] ad 70 [2] af 71 [2] b4 77 [2] a8 70 [2] b4 5f }

  condition:
    any of them
}