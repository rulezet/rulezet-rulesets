rule TTP_XOR_QUAD_CurrentVersionRun_da2d {
  strings:
    $key_da2d = { 89 42 [2] ad 4c [2] 86 60 [2] a8 42 [2] bc 59 [2] b3 43 [2] ad 5e [2] af 5f [2] b4 59 [2] a8 5e [2] b4 71 }

  condition:
    any of them
}