rule TTP_XOR_QUAD_CurrentVersionRun_d0e0 {
  strings:
    $key_d0e0 = { 83 8f [2] a7 81 [2] 8c ad [2] a2 8f [2] b6 94 [2] b9 8e [2] a7 93 [2] a5 92 [2] be 94 [2] a2 93 [2] be bc }

  condition:
    any of them
}