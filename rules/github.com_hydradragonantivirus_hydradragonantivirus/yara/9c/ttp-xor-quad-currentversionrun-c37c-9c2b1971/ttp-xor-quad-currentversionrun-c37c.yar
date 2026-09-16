rule TTP_XOR_QUAD_CurrentVersionRun_c37c {
  strings:
    $key_c37c = { 90 13 [2] b4 1d [2] 9f 31 [2] b1 13 [2] a5 08 [2] aa 12 [2] b4 0f [2] b6 0e [2] ad 08 [2] b1 0f [2] ad 20 }

  condition:
    any of them
}