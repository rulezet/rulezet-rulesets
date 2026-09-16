rule TTP_XOR_QUAD_CurrentVersionRun_c16c {
  strings:
    $key_c16c = { 92 03 [2] b6 0d [2] 9d 21 [2] b3 03 [2] a7 18 [2] a8 02 [2] b6 1f [2] b4 1e [2] af 18 [2] b3 1f [2] af 30 }

  condition:
    any of them
}