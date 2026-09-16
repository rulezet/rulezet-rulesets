rule TTP_XOR_QUAD_CurrentVersionRun_d02c {
  strings:
    $key_d02c = { 83 43 [2] a7 4d [2] 8c 61 [2] a2 43 [2] b6 58 [2] b9 42 [2] a7 5f [2] a5 5e [2] be 58 [2] a2 5f [2] be 70 }

  condition:
    any of them
}