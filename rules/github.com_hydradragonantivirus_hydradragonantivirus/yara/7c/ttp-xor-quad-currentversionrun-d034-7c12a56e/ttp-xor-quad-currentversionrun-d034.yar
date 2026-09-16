rule TTP_XOR_QUAD_CurrentVersionRun_d034 {
  strings:
    $key_d034 = { 83 5b [2] a7 55 [2] 8c 79 [2] a2 5b [2] b6 40 [2] b9 5a [2] a7 47 [2] a5 46 [2] be 40 [2] a2 47 [2] be 68 }

  condition:
    any of them
}