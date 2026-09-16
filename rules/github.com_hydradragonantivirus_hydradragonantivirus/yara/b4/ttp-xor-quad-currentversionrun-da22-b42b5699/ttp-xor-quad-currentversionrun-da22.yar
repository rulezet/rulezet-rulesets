rule TTP_XOR_QUAD_CurrentVersionRun_da22 {
  strings:
    $key_da22 = { 89 4d [2] ad 43 [2] 86 6f [2] a8 4d [2] bc 56 [2] b3 4c [2] ad 51 [2] af 50 [2] b4 56 [2] a8 51 [2] b4 7e }

  condition:
    any of them
}