rule TTP_XOR_QUAD_CurrentVersionRun_d039 {
  strings:
    $key_d039 = { 83 56 [2] a7 58 [2] 8c 74 [2] a2 56 [2] b6 4d [2] b9 57 [2] a7 4a [2] a5 4b [2] be 4d [2] a2 4a [2] be 65 }

  condition:
    any of them
}