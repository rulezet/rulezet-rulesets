rule TTP_XOR_QUAD_CurrentVersionRun_daff {
  strings:
    $key_daff = { 89 90 [2] ad 9e [2] 86 b2 [2] a8 90 [2] bc 8b [2] b3 91 [2] ad 8c [2] af 8d [2] b4 8b [2] a8 8c [2] b4 a3 }

  condition:
    any of them
}