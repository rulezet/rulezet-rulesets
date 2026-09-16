rule TTP_XOR_QUAD_CurrentVersionRun_daf1 {
  strings:
    $key_daf1 = { 89 9e [2] ad 90 [2] 86 bc [2] a8 9e [2] bc 85 [2] b3 9f [2] ad 82 [2] af 83 [2] b4 85 [2] a8 82 [2] b4 ad }

  condition:
    any of them
}