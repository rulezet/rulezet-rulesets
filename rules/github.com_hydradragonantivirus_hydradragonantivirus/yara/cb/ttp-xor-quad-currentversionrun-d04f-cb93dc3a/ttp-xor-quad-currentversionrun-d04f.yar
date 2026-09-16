rule TTP_XOR_QUAD_CurrentVersionRun_d04f {
  strings:
    $key_d04f = { 83 20 [2] a7 2e [2] 8c 02 [2] a2 20 [2] b6 3b [2] b9 21 [2] a7 3c [2] a5 3d [2] be 3b [2] a2 3c [2] be 13 }

  condition:
    any of them
}