rule TTP_XOR_QUAD_CurrentVersionRun_d068 {
  strings:
    $key_d068 = { 83 07 [2] a7 09 [2] 8c 25 [2] a2 07 [2] b6 1c [2] b9 06 [2] a7 1b [2] a5 1a [2] be 1c [2] a2 1b [2] be 34 }

  condition:
    any of them
}