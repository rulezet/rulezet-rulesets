rule TTP_XOR_QUAD_CurrentVersionRun_d045 {
  strings:
    $key_d045 = { 83 2a [2] a7 24 [2] 8c 08 [2] a2 2a [2] b6 31 [2] b9 2b [2] a7 36 [2] a5 37 [2] be 31 [2] a2 36 [2] be 19 }

  condition:
    any of them
}