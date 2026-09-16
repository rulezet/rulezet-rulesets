rule TTP_XOR_QUAD_CurrentVersionRun_dacd {
  strings:
    $key_dacd = { 89 a2 [2] ad ac [2] 86 80 [2] a8 a2 [2] bc b9 [2] b3 a3 [2] ad be [2] af bf [2] b4 b9 [2] a8 be [2] b4 91 }

  condition:
    any of them
}