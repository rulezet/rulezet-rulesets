rule TTP_XOR_QUAD_CurrentVersionRun_d050 {
  strings:
    $key_d050 = { 83 3f [2] a7 31 [2] 8c 1d [2] a2 3f [2] b6 24 [2] b9 3e [2] a7 23 [2] a5 22 [2] be 24 [2] a2 23 [2] be 0c }

  condition:
    any of them
}