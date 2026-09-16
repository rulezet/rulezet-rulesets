rule TTP_XOR_QUAD_CurrentVersionRun_c16d {
  strings:
    $key_c16d = { 92 02 [2] b6 0c [2] 9d 20 [2] b3 02 [2] a7 19 [2] a8 03 [2] b6 1e [2] b4 1f [2] af 19 [2] b3 1e [2] af 31 }

  condition:
    any of them
}