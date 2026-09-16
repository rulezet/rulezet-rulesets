rule TTP_XOR_QUAD_CurrentVersionRun_e8fc {
  strings:
    $key_e8fc = { bb 93 [2] 9f 9d [2] b4 b1 [2] 9a 93 [2] 8e 88 [2] 81 92 [2] 9f 8f [2] 9d 8e [2] 86 88 [2] 9a 8f [2] 86 a0 }

  condition:
    any of them
}