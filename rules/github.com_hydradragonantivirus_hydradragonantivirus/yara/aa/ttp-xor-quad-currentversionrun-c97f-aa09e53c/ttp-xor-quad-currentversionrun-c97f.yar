rule TTP_XOR_QUAD_CurrentVersionRun_c97f {
  strings:
    $key_c97f = { 9a 10 [2] be 1e [2] 95 32 [2] bb 10 [2] af 0b [2] a0 11 [2] be 0c [2] bc 0d [2] a7 0b [2] bb 0c [2] a7 23 }

  condition:
    any of them
}