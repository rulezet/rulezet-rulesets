rule TTP_XOR_QUAD_CurrentVersionRun_c5fa {
  strings:
    $key_c5fa = { 96 95 [2] b2 9b [2] 99 b7 [2] b7 95 [2] a3 8e [2] ac 94 [2] b2 89 [2] b0 88 [2] ab 8e [2] b7 89 [2] ab a6 }

  condition:
    any of them
}