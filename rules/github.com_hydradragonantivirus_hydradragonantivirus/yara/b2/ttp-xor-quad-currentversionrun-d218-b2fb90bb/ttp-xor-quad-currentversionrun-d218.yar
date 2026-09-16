rule TTP_XOR_QUAD_CurrentVersionRun_d218 {
  strings:
    $key_d218 = { 81 77 [2] a5 79 [2] 8e 55 [2] a0 77 [2] b4 6c [2] bb 76 [2] a5 6b [2] a7 6a [2] bc 6c [2] a0 6b [2] bc 44 }

  condition:
    any of them
}