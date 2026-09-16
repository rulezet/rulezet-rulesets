rule TTP_XOR_QUAD_CurrentVersionRun_c133 {
  strings:
    $key_c133 = { 92 5c [2] b6 52 [2] 9d 7e [2] b3 5c [2] a7 47 [2] a8 5d [2] b6 40 [2] b4 41 [2] af 47 [2] b3 40 [2] af 6f }

  condition:
    any of them
}