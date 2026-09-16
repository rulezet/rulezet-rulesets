rule TTP_XOR_QUAD_CurrentVersionRun_8853 {
  strings:
    $key_8853 = { db 3c [2] ff 32 [2] d4 1e [2] fa 3c [2] ee 27 [2] e1 3d [2] ff 20 [2] fd 21 [2] e6 27 [2] fa 20 [2] e6 0f }

  condition:
    any of them
}