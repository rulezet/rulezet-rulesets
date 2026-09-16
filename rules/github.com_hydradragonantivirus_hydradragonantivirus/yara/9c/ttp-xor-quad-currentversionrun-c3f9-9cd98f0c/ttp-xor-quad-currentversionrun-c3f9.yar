rule TTP_XOR_QUAD_CurrentVersionRun_c3f9 {
  strings:
    $key_c3f9 = { 90 96 [2] b4 98 [2] 9f b4 [2] b1 96 [2] a5 8d [2] aa 97 [2] b4 8a [2] b6 8b [2] ad 8d [2] b1 8a [2] ad a5 }

  condition:
    any of them
}