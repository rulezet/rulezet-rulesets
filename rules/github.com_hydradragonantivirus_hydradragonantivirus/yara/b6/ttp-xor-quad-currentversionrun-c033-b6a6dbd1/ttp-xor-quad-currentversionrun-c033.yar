rule TTP_XOR_QUAD_CurrentVersionRun_c033 {
  strings:
    $key_c033 = { 93 5c [2] b7 52 [2] 9c 7e [2] b2 5c [2] a6 47 [2] a9 5d [2] b7 40 [2] b5 41 [2] ae 47 [2] b2 40 [2] ae 6f }

  condition:
    any of them
}