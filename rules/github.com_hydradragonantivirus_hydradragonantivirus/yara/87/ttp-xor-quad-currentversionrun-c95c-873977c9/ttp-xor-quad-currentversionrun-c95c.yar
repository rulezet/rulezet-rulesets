rule TTP_XOR_QUAD_CurrentVersionRun_c95c {
  strings:
    $key_c95c = { 9a 33 [2] be 3d [2] 95 11 [2] bb 33 [2] af 28 [2] a0 32 [2] be 2f [2] bc 2e [2] a7 28 [2] bb 2f [2] a7 00 }

  condition:
    any of them
}