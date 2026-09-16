rule TTP_XOR_QUAD_CurrentVersionRun_dc53 {
  strings:
    $key_dc53 = { 8f 3c [2] ab 32 [2] 80 1e [2] ae 3c [2] ba 27 [2] b5 3d [2] ab 20 [2] a9 21 [2] b2 27 [2] ae 20 [2] b2 0f }

  condition:
    any of them
}