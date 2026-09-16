rule TTP_XOR_QUAD_CurrentVersionRun_dc4f {
  strings:
    $key_dc4f = { 8f 20 [2] ab 2e [2] 80 02 [2] ae 20 [2] ba 3b [2] b5 21 [2] ab 3c [2] a9 3d [2] b2 3b [2] ae 3c [2] b2 13 }

  condition:
    any of them
}