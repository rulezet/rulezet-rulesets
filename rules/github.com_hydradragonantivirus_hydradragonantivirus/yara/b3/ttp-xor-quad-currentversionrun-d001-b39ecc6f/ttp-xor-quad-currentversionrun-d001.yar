rule TTP_XOR_QUAD_CurrentVersionRun_d001 {
  strings:
    $key_d001 = { 83 6e [2] a7 60 [2] 8c 4c [2] a2 6e [2] b6 75 [2] b9 6f [2] a7 72 [2] a5 73 [2] be 75 [2] a2 72 [2] be 5d }

  condition:
    any of them
}