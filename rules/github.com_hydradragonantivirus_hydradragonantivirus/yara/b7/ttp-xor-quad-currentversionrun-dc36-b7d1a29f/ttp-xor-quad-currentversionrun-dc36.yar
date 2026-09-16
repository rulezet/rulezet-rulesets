rule TTP_XOR_QUAD_CurrentVersionRun_dc36 {
  strings:
    $key_dc36 = { 8f 59 [2] ab 57 [2] 80 7b [2] ae 59 [2] ba 42 [2] b5 58 [2] ab 45 [2] a9 44 [2] b2 42 [2] ae 45 [2] b2 6a }

  condition:
    any of them
}