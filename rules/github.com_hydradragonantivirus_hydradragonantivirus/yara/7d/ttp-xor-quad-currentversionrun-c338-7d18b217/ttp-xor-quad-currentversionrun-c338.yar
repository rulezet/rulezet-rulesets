rule TTP_XOR_QUAD_CurrentVersionRun_c338 {
  strings:
    $key_c338 = { 90 57 [2] b4 59 [2] 9f 75 [2] b1 57 [2] a5 4c [2] aa 56 [2] b4 4b [2] b6 4a [2] ad 4c [2] b1 4b [2] ad 64 }

  condition:
    any of them
}