rule TTP_XOR_QUAD_CurrentVersionRun_c62a {
  strings:
    $key_c62a = { 95 45 [2] b1 4b [2] 9a 67 [2] b4 45 [2] a0 5e [2] af 44 [2] b1 59 [2] b3 58 [2] a8 5e [2] b4 59 [2] a8 76 }

  condition:
    any of them
}