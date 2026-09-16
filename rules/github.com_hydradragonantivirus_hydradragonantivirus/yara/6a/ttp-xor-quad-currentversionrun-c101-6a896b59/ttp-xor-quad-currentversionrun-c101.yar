rule TTP_XOR_QUAD_CurrentVersionRun_c101 {
  strings:
    $key_c101 = { 92 6e [2] b6 60 [2] 9d 4c [2] b3 6e [2] a7 75 [2] a8 6f [2] b6 72 [2] b4 73 [2] af 75 [2] b3 72 [2] af 5d }

  condition:
    any of them
}