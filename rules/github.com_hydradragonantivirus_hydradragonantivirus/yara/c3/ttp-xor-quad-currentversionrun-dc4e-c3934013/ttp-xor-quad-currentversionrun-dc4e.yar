rule TTP_XOR_QUAD_CurrentVersionRun_dc4e {
  strings:
    $key_dc4e = { 8f 21 [2] ab 2f [2] 80 03 [2] ae 21 [2] ba 3a [2] b5 20 [2] ab 3d [2] a9 3c [2] b2 3a [2] ae 3d [2] b2 12 }

  condition:
    any of them
}