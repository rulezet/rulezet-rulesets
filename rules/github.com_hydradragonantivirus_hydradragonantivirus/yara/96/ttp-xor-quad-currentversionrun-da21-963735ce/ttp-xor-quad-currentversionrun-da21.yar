rule TTP_XOR_QUAD_CurrentVersionRun_da21 {
  strings:
    $key_da21 = { 89 4e [2] ad 40 [2] 86 6c [2] a8 4e [2] bc 55 [2] b3 4f [2] ad 52 [2] af 53 [2] b4 55 [2] a8 52 [2] b4 7d }

  condition:
    any of them
}