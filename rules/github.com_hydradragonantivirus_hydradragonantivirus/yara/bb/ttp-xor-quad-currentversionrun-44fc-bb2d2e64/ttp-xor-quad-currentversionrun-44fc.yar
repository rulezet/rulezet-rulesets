rule TTP_XOR_QUAD_CurrentVersionRun_44fc {
  strings:
    $key_44fc = { 17 93 [2] 33 9d [2] 18 b1 [2] 36 93 [2] 22 88 [2] 2d 92 [2] 33 8f [2] 31 8e [2] 2a 88 [2] 36 8f [2] 2a a0 }

  condition:
    any of them
}