rule TTP_XOR_QUAD_CurrentVersionRun_c439 {
  strings:
    $key_c439 = { 97 56 [2] b3 58 [2] 98 74 [2] b6 56 [2] a2 4d [2] ad 57 [2] b3 4a [2] b1 4b [2] aa 4d [2] b6 4a [2] aa 65 }

  condition:
    any of them
}