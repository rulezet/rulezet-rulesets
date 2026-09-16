rule TTP_XOR_QUAD_CurrentVersionRun_e9fc {
  strings:
    $key_e9fc = { ba 93 [2] 9e 9d [2] b5 b1 [2] 9b 93 [2] 8f 88 [2] 80 92 [2] 9e 8f [2] 9c 8e [2] 87 88 [2] 9b 8f [2] 87 a0 }

  condition:
    any of them
}