rule TTP_XOR_QUAD_CurrentVersionRun_da12 {
  strings:
    $key_da12 = { 89 7d [2] ad 73 [2] 86 5f [2] a8 7d [2] bc 66 [2] b3 7c [2] ad 61 [2] af 60 [2] b4 66 [2] a8 61 [2] b4 4e }

  condition:
    any of them
}