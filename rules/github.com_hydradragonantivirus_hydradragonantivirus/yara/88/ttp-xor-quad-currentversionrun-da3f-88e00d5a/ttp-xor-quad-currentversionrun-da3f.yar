rule TTP_XOR_QUAD_CurrentVersionRun_da3f {
  strings:
    $key_da3f = { 89 50 [2] ad 5e [2] 86 72 [2] a8 50 [2] bc 4b [2] b3 51 [2] ad 4c [2] af 4d [2] b4 4b [2] a8 4c [2] b4 63 }

  condition:
    any of them
}