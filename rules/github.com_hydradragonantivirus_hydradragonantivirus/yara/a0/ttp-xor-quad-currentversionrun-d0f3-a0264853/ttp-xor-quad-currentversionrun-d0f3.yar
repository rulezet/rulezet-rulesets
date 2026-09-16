rule TTP_XOR_QUAD_CurrentVersionRun_d0f3 {
  strings:
    $key_d0f3 = { 83 9c [2] a7 92 [2] 8c be [2] a2 9c [2] b6 87 [2] b9 9d [2] a7 80 [2] a5 81 [2] be 87 [2] a2 80 [2] be af }

  condition:
    any of them
}