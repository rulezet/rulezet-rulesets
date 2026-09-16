rule TTP_XOR_QUAD_CurrentVersionRun_dc2d {
  strings:
    $key_dc2d = { 8f 42 [2] ab 4c [2] 80 60 [2] ae 42 [2] ba 59 [2] b5 43 [2] ab 5e [2] a9 5f [2] b2 59 [2] ae 5e [2] b2 71 }

  condition:
    any of them
}