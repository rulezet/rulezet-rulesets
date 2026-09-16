rule TTP_XOR_QUAD_CurrentVersionRun_d7fc {
  strings:
    $key_d7fc = { 84 93 [2] a0 9d [2] 8b b1 [2] a5 93 [2] b1 88 [2] be 92 [2] a0 8f [2] a2 8e [2] b9 88 [2] a5 8f [2] b9 a0 }

  condition:
    any of them
}