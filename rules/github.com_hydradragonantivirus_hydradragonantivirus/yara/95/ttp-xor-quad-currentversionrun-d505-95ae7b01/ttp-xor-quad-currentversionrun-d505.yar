rule TTP_XOR_QUAD_CurrentVersionRun_d505 {
  strings:
    $key_d505 = { 86 6a [2] a2 64 [2] 89 48 [2] a7 6a [2] b3 71 [2] bc 6b [2] a2 76 [2] a0 77 [2] bb 71 [2] a7 76 [2] bb 59 }

  condition:
    any of them
}