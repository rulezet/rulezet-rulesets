rule TTP_XOR_QUAD_CurrentVersionRun_de13 {
  strings:
    $key_de13 = { 8d 7c [2] a9 72 [2] 82 5e [2] ac 7c [2] b8 67 [2] b7 7d [2] a9 60 [2] ab 61 [2] b0 67 [2] ac 60 [2] b0 4f }

  condition:
    any of them
}