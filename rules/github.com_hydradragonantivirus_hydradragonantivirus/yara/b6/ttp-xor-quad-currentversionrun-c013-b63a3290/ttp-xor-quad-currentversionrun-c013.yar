rule TTP_XOR_QUAD_CurrentVersionRun_c013 {
  strings:
    $key_c013 = { 93 7c [2] b7 72 [2] 9c 5e [2] b2 7c [2] a6 67 [2] a9 7d [2] b7 60 [2] b5 61 [2] ae 67 [2] b2 60 [2] ae 4f }

  condition:
    any of them
}