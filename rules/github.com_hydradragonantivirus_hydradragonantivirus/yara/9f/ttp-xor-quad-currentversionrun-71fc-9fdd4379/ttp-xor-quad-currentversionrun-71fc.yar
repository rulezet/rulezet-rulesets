rule TTP_XOR_QUAD_CurrentVersionRun_71fc {
  strings:
    $key_71fc = { 22 93 [2] 06 9d [2] 2d b1 [2] 03 93 [2] 17 88 [2] 18 92 [2] 06 8f [2] 04 8e [2] 1f 88 [2] 03 8f [2] 1f a0 }

  condition:
    any of them
}