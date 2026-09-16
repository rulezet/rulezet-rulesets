rule TTP_XOR_QUAD_CurrentVersionRun_da05 {
  strings:
    $key_da05 = { 89 6a [2] ad 64 [2] 86 48 [2] a8 6a [2] bc 71 [2] b3 6b [2] ad 76 [2] af 77 [2] b4 71 [2] a8 76 [2] b4 59 }

  condition:
    any of them
}