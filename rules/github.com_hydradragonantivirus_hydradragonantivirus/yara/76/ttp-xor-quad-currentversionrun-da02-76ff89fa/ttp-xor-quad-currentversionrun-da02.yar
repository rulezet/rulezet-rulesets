rule TTP_XOR_QUAD_CurrentVersionRun_da02 {
  strings:
    $key_da02 = { 89 6d [2] ad 63 [2] 86 4f [2] a8 6d [2] bc 76 [2] b3 6c [2] ad 71 [2] af 70 [2] b4 76 [2] a8 71 [2] b4 5e }

  condition:
    any of them
}