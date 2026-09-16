rule TTP_XOR_QUAD_CurrentVersionRun_da38 {
  strings:
    $key_da38 = { 89 57 [2] ad 59 [2] 86 75 [2] a8 57 [2] bc 4c [2] b3 56 [2] ad 4b [2] af 4a [2] b4 4c [2] a8 4b [2] b4 64 }

  condition:
    any of them
}