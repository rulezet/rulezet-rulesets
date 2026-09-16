rule TTP_XOR_QUAD_CurrentVersionRun_c95f {
  strings:
    $key_c95f = { 9a 30 [2] be 3e [2] 95 12 [2] bb 30 [2] af 2b [2] a0 31 [2] be 2c [2] bc 2d [2] a7 2b [2] bb 2c [2] a7 03 }

  condition:
    any of them
}