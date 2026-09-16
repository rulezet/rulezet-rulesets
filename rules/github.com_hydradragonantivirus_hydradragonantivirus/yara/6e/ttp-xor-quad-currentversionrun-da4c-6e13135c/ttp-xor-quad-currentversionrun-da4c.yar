rule TTP_XOR_QUAD_CurrentVersionRun_da4c {
  strings:
    $key_da4c = { 89 23 [2] ad 2d [2] 86 01 [2] a8 23 [2] bc 38 [2] b3 22 [2] ad 3f [2] af 3e [2] b4 38 [2] a8 3f [2] b4 10 }

  condition:
    any of them
}