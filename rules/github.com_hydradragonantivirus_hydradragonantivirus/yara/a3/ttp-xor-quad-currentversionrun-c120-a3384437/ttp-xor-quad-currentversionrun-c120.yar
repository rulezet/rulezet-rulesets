rule TTP_XOR_QUAD_CurrentVersionRun_c120 {
  strings:
    $key_c120 = { 92 4f [2] b6 41 [2] 9d 6d [2] b3 4f [2] a7 54 [2] a8 4e [2] b6 53 [2] b4 52 [2] af 54 [2] b3 53 [2] af 7c }

  condition:
    any of them
}