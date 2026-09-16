rule TTP_XOR_QUAD_CurrentVersionRun_54fc {
  strings:
    $key_54fc = { 07 93 [2] 23 9d [2] 08 b1 [2] 26 93 [2] 32 88 [2] 3d 92 [2] 23 8f [2] 21 8e [2] 3a 88 [2] 26 8f [2] 3a a0 }

  condition:
    any of them
}