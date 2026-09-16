rule TTP_XOR_QUAD_CurrentVersionRun_c17c {
  strings:
    $key_c17c = { 92 13 [2] b6 1d [2] 9d 31 [2] b3 13 [2] a7 08 [2] a8 12 [2] b6 0f [2] b4 0e [2] af 08 [2] b3 0f [2] af 20 }

  condition:
    any of them
}