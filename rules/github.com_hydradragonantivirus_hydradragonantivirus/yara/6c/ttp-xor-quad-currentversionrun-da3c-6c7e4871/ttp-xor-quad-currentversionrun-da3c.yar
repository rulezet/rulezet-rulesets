rule TTP_XOR_QUAD_CurrentVersionRun_da3c {
  strings:
    $key_da3c = { 89 53 [2] ad 5d [2] 86 71 [2] a8 53 [2] bc 48 [2] b3 52 [2] ad 4f [2] af 4e [2] b4 48 [2] a8 4f [2] b4 60 }

  condition:
    any of them
}