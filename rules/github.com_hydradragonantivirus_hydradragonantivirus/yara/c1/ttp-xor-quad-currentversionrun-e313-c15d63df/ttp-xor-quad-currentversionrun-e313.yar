rule TTP_XOR_QUAD_CurrentVersionRun_e313 {
  strings:
    $key_e313 = { b0 7c [2] 94 72 [2] bf 5e [2] 91 7c [2] 85 67 [2] 8a 7d [2] 94 60 [2] 96 61 [2] 8d 67 [2] 91 60 [2] 8d 4f }

  condition:
    any of them
}