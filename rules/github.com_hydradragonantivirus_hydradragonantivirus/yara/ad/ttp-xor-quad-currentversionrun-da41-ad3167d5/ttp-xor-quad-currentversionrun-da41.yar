rule TTP_XOR_QUAD_CurrentVersionRun_da41 {
  strings:
    $key_da41 = { 89 2e [2] ad 20 [2] 86 0c [2] a8 2e [2] bc 35 [2] b3 2f [2] ad 32 [2] af 33 [2] b4 35 [2] a8 32 [2] b4 1d }

  condition:
    any of them
}