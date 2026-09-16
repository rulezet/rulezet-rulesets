rule TTP_XOR_QUAD_CurrentVersionRun_c12d {
  strings:
    $key_c12d = { 92 42 [2] b6 4c [2] 9d 60 [2] b3 42 [2] a7 59 [2] a8 43 [2] b6 5e [2] b4 5f [2] af 59 [2] b3 5e [2] af 71 }

  condition:
    any of them
}