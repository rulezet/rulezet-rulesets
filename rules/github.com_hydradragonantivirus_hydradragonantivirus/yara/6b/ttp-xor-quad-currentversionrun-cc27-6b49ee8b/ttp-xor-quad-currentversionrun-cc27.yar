rule TTP_XOR_QUAD_CurrentVersionRun_cc27 {
  strings:
    $key_cc27 = { 9f 48 [2] bb 46 [2] 90 6a [2] be 48 [2] aa 53 [2] a5 49 [2] bb 54 [2] b9 55 [2] a2 53 [2] be 54 [2] a2 7b }

  condition:
    any of them
}