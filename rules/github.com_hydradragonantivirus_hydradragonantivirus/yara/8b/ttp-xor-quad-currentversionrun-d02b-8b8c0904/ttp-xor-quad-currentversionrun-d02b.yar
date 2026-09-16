rule TTP_XOR_QUAD_CurrentVersionRun_d02b {
  strings:
    $key_d02b = { 83 44 [2] a7 4a [2] 8c 66 [2] a2 44 [2] b6 5f [2] b9 45 [2] a7 58 [2] a5 59 [2] be 5f [2] a2 58 [2] be 77 }

  condition:
    any of them
}