rule TTP_XOR_QUAD_CurrentVersionRun_8213 {
  strings:
    $key_8213 = { d1 7c [2] f5 72 [2] de 5e [2] f0 7c [2] e4 67 [2] eb 7d [2] f5 60 [2] f7 61 [2] ec 67 [2] f0 60 [2] ec 4f }

  condition:
    any of them
}