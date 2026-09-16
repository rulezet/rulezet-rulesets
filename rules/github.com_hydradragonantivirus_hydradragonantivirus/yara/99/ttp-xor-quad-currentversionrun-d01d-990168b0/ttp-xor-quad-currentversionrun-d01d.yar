rule TTP_XOR_QUAD_CurrentVersionRun_d01d {
  strings:
    $key_d01d = { 83 72 [2] a7 7c [2] 8c 50 [2] a2 72 [2] b6 69 [2] b9 73 [2] a7 6e [2] a5 6f [2] be 69 [2] a2 6e [2] be 41 }

  condition:
    any of them
}