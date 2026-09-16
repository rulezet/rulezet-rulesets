rule TTP_XOR_QUAD_CurrentVersionRun_c071 {
  strings:
    $key_c071 = { 93 1e [2] b7 10 [2] 9c 3c [2] b2 1e [2] a6 05 [2] a9 1f [2] b7 02 [2] b5 03 [2] ae 05 [2] b2 02 [2] ae 2d }

  condition:
    any of them
}