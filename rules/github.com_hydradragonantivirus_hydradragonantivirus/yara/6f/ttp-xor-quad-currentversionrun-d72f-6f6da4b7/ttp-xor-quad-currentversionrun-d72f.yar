rule TTP_XOR_QUAD_CurrentVersionRun_d72f {
  strings:
    $key_d72f = { 84 40 [2] a0 4e [2] 8b 62 [2] a5 40 [2] b1 5b [2] be 41 [2] a0 5c [2] a2 5d [2] b9 5b [2] a5 5c [2] b9 73 }

  condition:
    any of them
}