rule TTP_XOR_QUAD_CurrentVersionRun_d01b {
  strings:
    $key_d01b = { 83 74 [2] a7 7a [2] 8c 56 [2] a2 74 [2] b6 6f [2] b9 75 [2] a7 68 [2] a5 69 [2] be 6f [2] a2 68 [2] be 47 }

  condition:
    any of them
}