rule TTP_XOR_QUAD_CurrentVersionRun_dafd {
  strings:
    $key_dafd = { 89 92 [2] ad 9c [2] 86 b0 [2] a8 92 [2] bc 89 [2] b3 93 [2] ad 8e [2] af 8f [2] b4 89 [2] a8 8e [2] b4 a1 }

  condition:
    any of them
}