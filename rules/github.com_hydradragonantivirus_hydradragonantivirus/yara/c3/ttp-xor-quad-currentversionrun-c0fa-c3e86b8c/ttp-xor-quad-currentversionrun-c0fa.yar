rule TTP_XOR_QUAD_CurrentVersionRun_c0fa {
  strings:
    $key_c0fa = { 93 95 [2] b7 9b [2] 9c b7 [2] b2 95 [2] a6 8e [2] a9 94 [2] b7 89 [2] b5 88 [2] ae 8e [2] b2 89 [2] ae a6 }

  condition:
    any of them
}