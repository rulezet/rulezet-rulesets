rule TTP_XOR_QUAD_CurrentVersionRun_f753 {
  strings:
    $key_f753 = { a4 3c [2] 80 32 [2] ab 1e [2] 85 3c [2] 91 27 [2] 9e 3d [2] 80 20 [2] 82 21 [2] 99 27 [2] 85 20 [2] 99 0f }

  condition:
    any of them
}