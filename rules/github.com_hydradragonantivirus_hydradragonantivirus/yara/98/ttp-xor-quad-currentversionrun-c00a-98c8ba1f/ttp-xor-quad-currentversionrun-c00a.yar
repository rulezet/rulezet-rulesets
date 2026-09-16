rule TTP_XOR_QUAD_CurrentVersionRun_c00a {
  strings:
    $key_c00a = { 93 65 [2] b7 6b [2] 9c 47 [2] b2 65 [2] a6 7e [2] a9 64 [2] b7 79 [2] b5 78 [2] ae 7e [2] b2 79 [2] ae 56 }

  condition:
    any of them
}