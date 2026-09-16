rule TTP_XOR_QUAD_CurrentVersionRun_defc {
  strings:
    $key_defc = { 8d 93 [2] a9 9d [2] 82 b1 [2] ac 93 [2] b8 88 [2] b7 92 [2] a9 8f [2] ab 8e [2] b0 88 [2] ac 8f [2] b0 a0 }

  condition:
    any of them
}