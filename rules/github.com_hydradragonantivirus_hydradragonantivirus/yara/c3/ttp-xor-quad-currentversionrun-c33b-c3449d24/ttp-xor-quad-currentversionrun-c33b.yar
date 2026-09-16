rule TTP_XOR_QUAD_CurrentVersionRun_c33b {
  strings:
    $key_c33b = { 90 54 [2] b4 5a [2] 9f 76 [2] b1 54 [2] a5 4f [2] aa 55 [2] b4 48 [2] b6 49 [2] ad 4f [2] b1 48 [2] ad 67 }

  condition:
    any of them
}