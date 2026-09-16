rule TTP_XOR_QUAD_CurrentVersionRun_c04a {
  strings:
    $key_c04a = { 93 25 [2] b7 2b [2] 9c 07 [2] b2 25 [2] a6 3e [2] a9 24 [2] b7 39 [2] b5 38 [2] ae 3e [2] b2 39 [2] ae 16 }

  condition:
    any of them
}