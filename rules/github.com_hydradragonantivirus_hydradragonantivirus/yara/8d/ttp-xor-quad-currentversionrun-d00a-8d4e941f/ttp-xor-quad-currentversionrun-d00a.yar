rule TTP_XOR_QUAD_CurrentVersionRun_d00a {
  strings:
    $key_d00a = { 83 65 [2] a7 6b [2] 8c 47 [2] a2 65 [2] b6 7e [2] b9 64 [2] a7 79 [2] a5 78 [2] be 7e [2] a2 79 [2] be 56 }

  condition:
    any of them
}