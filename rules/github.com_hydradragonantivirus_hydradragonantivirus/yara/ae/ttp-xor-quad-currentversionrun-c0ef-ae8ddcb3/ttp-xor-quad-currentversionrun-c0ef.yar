rule TTP_XOR_QUAD_CurrentVersionRun_c0ef {
  strings:
    $key_c0ef = { 93 80 [2] b7 8e [2] 9c a2 [2] b2 80 [2] a6 9b [2] a9 81 [2] b7 9c [2] b5 9d [2] ae 9b [2] b2 9c [2] ae b3 }

  condition:
    any of them
}