rule TTP_XOR_QUAD_CurrentVersionRun_dff9 {
  strings:
    $key_dff9 = { 8c 96 [2] a8 98 [2] 83 b4 [2] ad 96 [2] b9 8d [2] b6 97 [2] a8 8a [2] aa 8b [2] b1 8d [2] ad 8a [2] b1 a5 }

  condition:
    any of them
}