rule TTP_XOR_QUAD_CurrentVersionRun_d006 {
  strings:
    $key_d006 = { 83 69 [2] a7 67 [2] 8c 4b [2] a2 69 [2] b6 72 [2] b9 68 [2] a7 75 [2] a5 74 [2] be 72 [2] a2 75 [2] be 5a }

  condition:
    any of them
}