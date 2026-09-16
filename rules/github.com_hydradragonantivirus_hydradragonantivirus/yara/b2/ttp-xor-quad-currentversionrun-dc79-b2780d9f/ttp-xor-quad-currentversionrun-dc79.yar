rule TTP_XOR_QUAD_CurrentVersionRun_dc79 {
  strings:
    $key_dc79 = { 8f 16 [2] ab 18 [2] 80 34 [2] ae 16 [2] ba 0d [2] b5 17 [2] ab 0a [2] a9 0b [2] b2 0d [2] ae 0a [2] b2 25 }

  condition:
    any of them
}