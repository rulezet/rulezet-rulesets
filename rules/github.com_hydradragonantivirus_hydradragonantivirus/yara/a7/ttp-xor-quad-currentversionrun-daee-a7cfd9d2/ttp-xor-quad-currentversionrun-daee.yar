rule TTP_XOR_QUAD_CurrentVersionRun_daee {
  strings:
    $key_daee = { 89 81 [2] ad 8f [2] 86 a3 [2] a8 81 [2] bc 9a [2] b3 80 [2] ad 9d [2] af 9c [2] b4 9a [2] a8 9d [2] b4 b2 }

  condition:
    any of them
}