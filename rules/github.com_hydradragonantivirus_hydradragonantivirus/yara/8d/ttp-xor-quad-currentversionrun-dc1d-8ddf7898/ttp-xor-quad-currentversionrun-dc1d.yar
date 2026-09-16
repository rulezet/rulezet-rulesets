rule TTP_XOR_QUAD_CurrentVersionRun_dc1d {
  strings:
    $key_dc1d = { 8f 72 [2] ab 7c [2] 80 50 [2] ae 72 [2] ba 69 [2] b5 73 [2] ab 6e [2] a9 6f [2] b2 69 [2] ae 6e [2] b2 41 }

  condition:
    any of them
}