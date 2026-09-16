rule TTP_XOR_QUAD_CurrentVersionRun_daf6 {
  strings:
    $key_daf6 = { 89 99 [2] ad 97 [2] 86 bb [2] a8 99 [2] bc 82 [2] b3 98 [2] ad 85 [2] af 84 [2] b4 82 [2] a8 85 [2] b4 aa }

  condition:
    any of them
}