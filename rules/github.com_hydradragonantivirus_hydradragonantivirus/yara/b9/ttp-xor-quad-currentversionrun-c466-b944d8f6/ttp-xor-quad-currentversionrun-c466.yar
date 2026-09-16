rule TTP_XOR_QUAD_CurrentVersionRun_c466 {
  strings:
    $key_c466 = { 97 09 [2] b3 07 [2] 98 2b [2] b6 09 [2] a2 12 [2] ad 08 [2] b3 15 [2] b1 14 [2] aa 12 [2] b6 15 [2] aa 3a }

  condition:
    any of them
}