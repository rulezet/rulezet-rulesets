rule TTP_XOR_QUAD_CurrentVersionRun_d0ef {
  strings:
    $key_d0ef = { 83 80 [2] a7 8e [2] 8c a2 [2] a2 80 [2] b6 9b [2] b9 81 [2] a7 9c [2] a5 9d [2] be 9b [2] a2 9c [2] be b3 }

  condition:
    any of them
}