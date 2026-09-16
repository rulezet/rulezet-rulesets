rule TTP_XOR_QUAD_CurrentVersionRun_daed {
  strings:
    $key_daed = { 89 82 [2] ad 8c [2] 86 a0 [2] a8 82 [2] bc 99 [2] b3 83 [2] ad 9e [2] af 9f [2] b4 99 [2] a8 9e [2] b4 b1 }

  condition:
    any of them
}