rule TTP_XOR_QUAD_CurrentVersionRun_71fd {
  strings:
    $key_71fd = { 22 92 [2] 06 9c [2] 2d b0 [2] 03 92 [2] 17 89 [2] 18 93 [2] 06 8e [2] 04 8f [2] 1f 89 [2] 03 8e [2] 1f a1 }

  condition:
    any of them
}