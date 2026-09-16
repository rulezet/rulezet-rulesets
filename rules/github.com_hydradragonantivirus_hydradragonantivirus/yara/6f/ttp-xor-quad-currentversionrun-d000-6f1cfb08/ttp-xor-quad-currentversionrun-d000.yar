rule TTP_XOR_QUAD_CurrentVersionRun_d000 {
  strings:
    $key_d000 = { 83 6f [2] a7 61 [2] 8c 4d [2] a2 6f [2] b6 74 [2] b9 6e [2] a7 73 [2] a5 72 [2] be 74 [2] a2 73 [2] be 5c }

  condition:
    any of them
}