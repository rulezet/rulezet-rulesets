rule TTP_XOR_QUAD_CurrentVersionRun_c0ec {
  strings:
    $key_c0ec = { 93 83 [2] b7 8d [2] 9c a1 [2] b2 83 [2] a6 98 [2] a9 82 [2] b7 9f [2] b5 9e [2] ae 98 [2] b2 9f [2] ae b0 }

  condition:
    any of them
}