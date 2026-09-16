rule TTP_XOR_QUAD_CurrentVersionRun_fa53 {
  strings:
    $key_fa53 = { a9 3c [2] 8d 32 [2] a6 1e [2] 88 3c [2] 9c 27 [2] 93 3d [2] 8d 20 [2] 8f 21 [2] 94 27 [2] 88 20 [2] 94 0f }

  condition:
    any of them
}