rule TTP_XOR_QUAD_CurrentVersionRun_c77f {
  strings:
    $key_c77f = { 94 10 [2] b0 1e [2] 9b 32 [2] b5 10 [2] a1 0b [2] ae 11 [2] b0 0c [2] b2 0d [2] a9 0b [2] b5 0c [2] a9 23 }

  condition:
    any of them
}