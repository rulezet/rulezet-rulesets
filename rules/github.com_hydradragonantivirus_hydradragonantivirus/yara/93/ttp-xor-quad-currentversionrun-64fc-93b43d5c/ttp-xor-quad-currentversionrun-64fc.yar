rule TTP_XOR_QUAD_CurrentVersionRun_64fc {
  strings:
    $key_64fc = { 37 93 [2] 13 9d [2] 38 b1 [2] 16 93 [2] 02 88 [2] 0d 92 [2] 13 8f [2] 11 8e [2] 0a 88 [2] 16 8f [2] 0a a0 }

  condition:
    any of them
}