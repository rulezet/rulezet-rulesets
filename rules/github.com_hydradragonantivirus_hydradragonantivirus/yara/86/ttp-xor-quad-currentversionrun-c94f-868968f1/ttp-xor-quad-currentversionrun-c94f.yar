rule TTP_XOR_QUAD_CurrentVersionRun_c94f {
  strings:
    $key_c94f = { 9a 20 [2] be 2e [2] 95 02 [2] bb 20 [2] af 3b [2] a0 21 [2] be 3c [2] bc 3d [2] a7 3b [2] bb 3c [2] a7 13 }

  condition:
    any of them
}