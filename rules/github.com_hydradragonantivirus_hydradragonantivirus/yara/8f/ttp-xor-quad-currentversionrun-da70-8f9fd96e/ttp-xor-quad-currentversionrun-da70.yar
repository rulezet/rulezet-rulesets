rule TTP_XOR_QUAD_CurrentVersionRun_da70 {
  strings:
    $key_da70 = { 89 1f [2] ad 11 [2] 86 3d [2] a8 1f [2] bc 04 [2] b3 1e [2] ad 03 [2] af 02 [2] b4 04 [2] a8 03 [2] b4 2c }

  condition:
    any of them
}