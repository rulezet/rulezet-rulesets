rule TTP_XOR_QUAD_CurrentVersionRun_dc75 {
  strings:
    $key_dc75 = { 8f 1a [2] ab 14 [2] 80 38 [2] ae 1a [2] ba 01 [2] b5 1b [2] ab 06 [2] a9 07 [2] b2 01 [2] ae 06 [2] b2 29 }

  condition:
    any of them
}