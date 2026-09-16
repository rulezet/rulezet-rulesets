rule TTP_XOR_QUAD_CurrentVersionRun_dce5 {
  strings:
    $key_dce5 = { 8f 8a [2] ab 84 [2] 80 a8 [2] ae 8a [2] ba 91 [2] b5 8b [2] ab 96 [2] a9 97 [2] b2 91 [2] ae 96 [2] b2 b9 }

  condition:
    any of them
}