rule TTP_XOR_QUAD_CurrentVersionRun_dcf5 {
  strings:
    $key_dcf5 = { 8f 9a [2] ab 94 [2] 80 b8 [2] ae 9a [2] ba 81 [2] b5 9b [2] ab 86 [2] a9 87 [2] b2 81 [2] ae 86 [2] b2 a9 }

  condition:
    any of them
}