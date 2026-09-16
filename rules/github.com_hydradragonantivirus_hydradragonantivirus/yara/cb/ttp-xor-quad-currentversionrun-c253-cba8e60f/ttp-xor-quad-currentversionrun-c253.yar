rule TTP_XOR_QUAD_CurrentVersionRun_c253 {
  strings:
    $key_c253 = { 91 3c [2] b5 32 [2] 9e 1e [2] b0 3c [2] a4 27 [2] ab 3d [2] b5 20 [2] b7 21 [2] ac 27 [2] b0 20 [2] ac 0f }

  condition:
    any of them
}