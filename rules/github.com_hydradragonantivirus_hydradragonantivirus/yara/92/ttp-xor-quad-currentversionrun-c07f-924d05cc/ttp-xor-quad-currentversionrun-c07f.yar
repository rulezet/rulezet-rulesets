rule TTP_XOR_QUAD_CurrentVersionRun_c07f {
  strings:
    $key_c07f = { 93 10 [2] b7 1e [2] 9c 32 [2] b2 10 [2] a6 0b [2] a9 11 [2] b7 0c [2] b5 0d [2] ae 0b [2] b2 0c [2] ae 23 }

  condition:
    any of them
}