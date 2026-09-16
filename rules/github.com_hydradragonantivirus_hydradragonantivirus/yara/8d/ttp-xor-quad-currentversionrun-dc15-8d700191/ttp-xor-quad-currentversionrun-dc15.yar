rule TTP_XOR_QUAD_CurrentVersionRun_dc15 {
  strings:
    $key_dc15 = { 8f 7a [2] ab 74 [2] 80 58 [2] ae 7a [2] ba 61 [2] b5 7b [2] ab 66 [2] a9 67 [2] b2 61 [2] ae 66 [2] b2 49 }

  condition:
    any of them
}