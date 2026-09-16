rule TTP_XOR_QUAD_CurrentVersionRun_dc46 {
  strings:
    $key_dc46 = { 8f 29 [2] ab 27 [2] 80 0b [2] ae 29 [2] ba 32 [2] b5 28 [2] ab 35 [2] a9 34 [2] b2 32 [2] ae 35 [2] b2 1a }

  condition:
    any of them
}