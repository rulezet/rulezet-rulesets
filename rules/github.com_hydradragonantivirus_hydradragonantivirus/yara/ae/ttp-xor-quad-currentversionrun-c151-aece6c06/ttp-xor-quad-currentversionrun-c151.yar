rule TTP_XOR_QUAD_CurrentVersionRun_c151 {
  strings:
    $key_c151 = { 92 3e [2] b6 30 [2] 9d 1c [2] b3 3e [2] a7 25 [2] a8 3f [2] b6 22 [2] b4 23 [2] af 25 [2] b3 22 [2] af 0d }

  condition:
    any of them
}