rule TTP_XOR_QUAD_CurrentVersionRun_d71f {
  strings:
    $key_d71f = { 84 70 [2] a0 7e [2] 8b 52 [2] a5 70 [2] b1 6b [2] be 71 [2] a0 6c [2] a2 6d [2] b9 6b [2] a5 6c [2] b9 43 }

  condition:
    any of them
}