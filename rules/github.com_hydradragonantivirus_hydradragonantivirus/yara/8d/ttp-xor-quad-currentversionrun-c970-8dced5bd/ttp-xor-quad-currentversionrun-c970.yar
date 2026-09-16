rule TTP_XOR_QUAD_CurrentVersionRun_c970 {
  strings:
    $key_c970 = { 9a 1f [2] be 11 [2] 95 3d [2] bb 1f [2] af 04 [2] a0 1e [2] be 03 [2] bc 02 [2] a7 04 [2] bb 03 [2] a7 2c }

  condition:
    any of them
}