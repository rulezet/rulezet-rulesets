rule TTP_XOR_QUAD_CurrentVersionRun_c40b {
  strings:
    $key_c40b = { 97 64 [2] b3 6a [2] 98 46 [2] b6 64 [2] a2 7f [2] ad 65 [2] b3 78 [2] b1 79 [2] aa 7f [2] b6 78 [2] aa 57 }

  condition:
    any of them
}