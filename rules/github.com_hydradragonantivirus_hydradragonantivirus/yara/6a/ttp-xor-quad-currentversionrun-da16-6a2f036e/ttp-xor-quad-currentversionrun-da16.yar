rule TTP_XOR_QUAD_CurrentVersionRun_da16 {
  strings:
    $key_da16 = { 89 79 [2] ad 77 [2] 86 5b [2] a8 79 [2] bc 62 [2] b3 78 [2] ad 65 [2] af 64 [2] b4 62 [2] a8 65 [2] b4 4a }

  condition:
    any of them
}