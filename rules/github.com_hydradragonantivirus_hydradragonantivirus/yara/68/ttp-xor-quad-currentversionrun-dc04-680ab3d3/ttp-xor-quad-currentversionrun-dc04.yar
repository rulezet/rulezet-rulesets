rule TTP_XOR_QUAD_CurrentVersionRun_dc04 {
  strings:
    $key_dc04 = { 8f 6b [2] ab 65 [2] 80 49 [2] ae 6b [2] ba 70 [2] b5 6a [2] ab 77 [2] a9 76 [2] b2 70 [2] ae 77 [2] b2 58 }

  condition:
    any of them
}