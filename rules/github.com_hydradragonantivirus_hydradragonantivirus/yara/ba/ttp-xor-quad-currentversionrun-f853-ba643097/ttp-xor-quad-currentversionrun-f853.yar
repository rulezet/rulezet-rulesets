rule TTP_XOR_QUAD_CurrentVersionRun_f853 {
  strings:
    $key_f853 = { ab 3c [2] 8f 32 [2] a4 1e [2] 8a 3c [2] 9e 27 [2] 91 3d [2] 8f 20 [2] 8d 21 [2] 96 27 [2] 8a 20 [2] 96 0f }

  condition:
    any of them
}