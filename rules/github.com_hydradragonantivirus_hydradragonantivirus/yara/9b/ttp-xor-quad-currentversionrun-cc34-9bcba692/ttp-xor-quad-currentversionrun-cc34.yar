rule TTP_XOR_QUAD_CurrentVersionRun_cc34 {
  strings:
    $key_cc34 = { 9f 5b [2] bb 55 [2] 90 79 [2] be 5b [2] aa 40 [2] a5 5a [2] bb 47 [2] b9 46 [2] a2 40 [2] be 47 [2] a2 68 }

  condition:
    any of them
}