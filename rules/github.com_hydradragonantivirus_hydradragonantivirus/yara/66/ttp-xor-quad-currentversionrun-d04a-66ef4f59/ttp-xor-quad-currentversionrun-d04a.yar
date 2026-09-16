rule TTP_XOR_QUAD_CurrentVersionRun_d04a {
  strings:
    $key_d04a = { 83 25 [2] a7 2b [2] 8c 07 [2] a2 25 [2] b6 3e [2] b9 24 [2] a7 39 [2] a5 38 [2] be 3e [2] a2 39 [2] be 16 }

  condition:
    any of them
}