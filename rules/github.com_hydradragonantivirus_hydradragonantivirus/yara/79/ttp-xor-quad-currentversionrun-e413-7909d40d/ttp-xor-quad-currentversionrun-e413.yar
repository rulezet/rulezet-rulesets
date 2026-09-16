rule TTP_XOR_QUAD_CurrentVersionRun_e413 {
  strings:
    $key_e413 = { b7 7c [2] 93 72 [2] b8 5e [2] 96 7c [2] 82 67 [2] 8d 7d [2] 93 60 [2] 91 61 [2] 8a 67 [2] 96 60 [2] 8a 4f }

  condition:
    any of them
}