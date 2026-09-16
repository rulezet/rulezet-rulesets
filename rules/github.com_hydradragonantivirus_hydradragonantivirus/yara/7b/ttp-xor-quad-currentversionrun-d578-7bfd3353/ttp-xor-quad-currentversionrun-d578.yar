rule TTP_XOR_QUAD_CurrentVersionRun_d578 {
  strings:
    $key_d578 = { 86 17 [2] a2 19 [2] 89 35 [2] a7 17 [2] b3 0c [2] bc 16 [2] a2 0b [2] a0 0a [2] bb 0c [2] a7 0b [2] bb 24 }

  condition:
    any of them
}