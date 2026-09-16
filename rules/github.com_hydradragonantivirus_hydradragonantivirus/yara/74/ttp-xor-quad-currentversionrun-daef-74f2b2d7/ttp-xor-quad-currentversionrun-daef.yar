rule TTP_XOR_QUAD_CurrentVersionRun_daef {
  strings:
    $key_daef = { 89 80 [2] ad 8e [2] 86 a2 [2] a8 80 [2] bc 9b [2] b3 81 [2] ad 9c [2] af 9d [2] b4 9b [2] a8 9c [2] b4 b3 }

  condition:
    any of them
}