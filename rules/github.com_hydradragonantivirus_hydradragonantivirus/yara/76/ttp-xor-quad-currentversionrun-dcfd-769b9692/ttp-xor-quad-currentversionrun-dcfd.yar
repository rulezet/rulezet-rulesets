rule TTP_XOR_QUAD_CurrentVersionRun_dcfd {
  strings:
    $key_dcfd = { 8f 92 [2] ab 9c [2] 80 b0 [2] ae 92 [2] ba 89 [2] b5 93 [2] ab 8e [2] a9 8f [2] b2 89 [2] ae 8e [2] b2 a1 }

  condition:
    any of them
}