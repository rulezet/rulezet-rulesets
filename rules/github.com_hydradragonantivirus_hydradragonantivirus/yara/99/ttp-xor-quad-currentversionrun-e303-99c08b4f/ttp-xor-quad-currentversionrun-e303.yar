rule TTP_XOR_QUAD_CurrentVersionRun_e303 {
  strings:
    $key_e303 = { b0 6c [2] 94 62 [2] bf 4e [2] 91 6c [2] 85 77 [2] 8a 6d [2] 94 70 [2] 96 71 [2] 8d 77 [2] 91 70 [2] 8d 5f }

  condition:
    any of them
}