rule TTP_XOR_QUAD_CurrentVersionRun_9313 {
  strings:
    $key_9313 = { c0 7c [2] e4 72 [2] cf 5e [2] e1 7c [2] f5 67 [2] fa 7d [2] e4 60 [2] e6 61 [2] fd 67 [2] e1 60 [2] fd 4f }

  condition:
    any of them
}