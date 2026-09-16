rule TTP_XOR_QUAD_CurrentVersionRun_dc14 {
  strings:
    $key_dc14 = { 8f 7b [2] ab 75 [2] 80 59 [2] ae 7b [2] ba 60 [2] b5 7a [2] ab 67 [2] a9 66 [2] b2 60 [2] ae 67 [2] b2 48 }

  condition:
    any of them
}