rule TTP_XOR_QUAD_CurrentVersionRun_d009 {
  strings:
    $key_d009 = { 83 66 [2] a7 68 [2] 8c 44 [2] a2 66 [2] b6 7d [2] b9 67 [2] a7 7a [2] a5 7b [2] be 7d [2] a2 7a [2] be 55 }

  condition:
    any of them
}