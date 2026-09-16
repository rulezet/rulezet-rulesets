rule TTP_XOR_QUAD_CurrentVersionRun_c913 {
  strings:
    $key_c913 = { 9a 7c [2] be 72 [2] 95 5e [2] bb 7c [2] af 67 [2] a0 7d [2] be 60 [2] bc 61 [2] a7 67 [2] bb 60 [2] a7 4f }

  condition:
    any of them
}