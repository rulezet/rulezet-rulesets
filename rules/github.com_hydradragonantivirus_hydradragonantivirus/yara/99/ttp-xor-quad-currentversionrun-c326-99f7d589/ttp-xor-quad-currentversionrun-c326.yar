rule TTP_XOR_QUAD_CurrentVersionRun_c326 {
  strings:
    $key_c326 = { 90 49 [2] b4 47 [2] 9f 6b [2] b1 49 [2] a5 52 [2] aa 48 [2] b4 55 [2] b6 54 [2] ad 52 [2] b1 55 [2] ad 7a }

  condition:
    any of them
}