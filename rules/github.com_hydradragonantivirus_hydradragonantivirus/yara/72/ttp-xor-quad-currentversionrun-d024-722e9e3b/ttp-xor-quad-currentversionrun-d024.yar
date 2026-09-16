rule TTP_XOR_QUAD_CurrentVersionRun_d024 {
  strings:
    $key_d024 = { 83 4b [2] a7 45 [2] 8c 69 [2] a2 4b [2] b6 50 [2] b9 4a [2] a7 57 [2] a5 56 [2] be 50 [2] a2 57 [2] be 78 }

  condition:
    any of them
}