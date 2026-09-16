rule TTP_XOR_QUAD_CurrentVersionRun_dc69 {
  strings:
    $key_dc69 = { 8f 06 [2] ab 08 [2] 80 24 [2] ae 06 [2] ba 1d [2] b5 07 [2] ab 1a [2] a9 1b [2] b2 1d [2] ae 1a [2] b2 35 }

  condition:
    any of them
}