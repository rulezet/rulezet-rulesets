rule TTP_XOR_QUAD_CurrentVersionRun_fd53 {
  strings:
    $key_fd53 = { ae 3c [2] 8a 32 [2] a1 1e [2] 8f 3c [2] 9b 27 [2] 94 3d [2] 8a 20 [2] 88 21 [2] 93 27 [2] 8f 20 [2] 93 0f }

  condition:
    any of them
}