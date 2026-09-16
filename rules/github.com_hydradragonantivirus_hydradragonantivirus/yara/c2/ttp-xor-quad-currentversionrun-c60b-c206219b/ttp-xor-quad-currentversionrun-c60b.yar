rule TTP_XOR_QUAD_CurrentVersionRun_c60b {
  strings:
    $key_c60b = { 95 64 [2] b1 6a [2] 9a 46 [2] b4 64 [2] a0 7f [2] af 65 [2] b1 78 [2] b3 79 [2] a8 7f [2] b4 78 [2] a8 57 }

  condition:
    any of them
}