rule TTP_XOR_QUAD_CurrentVersionRun_d07d {
  strings:
    $key_d07d = { 83 12 [2] a7 1c [2] 8c 30 [2] a2 12 [2] b6 09 [2] b9 13 [2] a7 0e [2] a5 0f [2] be 09 [2] a2 0e [2] be 21 }

  condition:
    any of them
}