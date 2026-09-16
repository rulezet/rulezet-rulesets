rule TTP_XOR_QUAD_CurrentVersionRun_c60a {
  strings:
    $key_c60a = { 95 65 [2] b1 6b [2] 9a 47 [2] b4 65 [2] a0 7e [2] af 64 [2] b1 79 [2] b3 78 [2] a8 7e [2] b4 79 [2] a8 56 }

  condition:
    any of them
}