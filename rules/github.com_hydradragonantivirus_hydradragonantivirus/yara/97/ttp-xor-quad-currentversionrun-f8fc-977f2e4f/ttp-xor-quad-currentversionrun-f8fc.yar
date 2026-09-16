rule TTP_XOR_QUAD_CurrentVersionRun_f8fc {
  strings:
    $key_f8fc = { ab 93 [2] 8f 9d [2] a4 b1 [2] 8a 93 [2] 9e 88 [2] 91 92 [2] 8f 8f [2] 8d 8e [2] 96 88 [2] 8a 8f [2] 96 a0 }

  condition:
    any of them
}