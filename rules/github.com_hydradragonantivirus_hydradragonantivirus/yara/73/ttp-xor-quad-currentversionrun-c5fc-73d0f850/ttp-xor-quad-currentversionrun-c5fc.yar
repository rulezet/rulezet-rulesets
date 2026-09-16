rule TTP_XOR_QUAD_CurrentVersionRun_c5fc {
  strings:
    $key_c5fc = { 96 93 [2] b2 9d [2] 99 b1 [2] b7 93 [2] a3 88 [2] ac 92 [2] b2 8f [2] b0 8e [2] ab 88 [2] b7 8f [2] ab a0 }

  condition:
    any of them
}