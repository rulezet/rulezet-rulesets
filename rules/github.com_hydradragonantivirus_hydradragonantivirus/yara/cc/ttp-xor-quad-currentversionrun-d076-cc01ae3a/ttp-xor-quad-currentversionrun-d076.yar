rule TTP_XOR_QUAD_CurrentVersionRun_d076 {
  strings:
    $key_d076 = { 83 19 [2] a7 17 [2] 8c 3b [2] a2 19 [2] b6 02 [2] b9 18 [2] a7 05 [2] a5 04 [2] be 02 [2] a2 05 [2] be 2a }

  condition:
    any of them
}