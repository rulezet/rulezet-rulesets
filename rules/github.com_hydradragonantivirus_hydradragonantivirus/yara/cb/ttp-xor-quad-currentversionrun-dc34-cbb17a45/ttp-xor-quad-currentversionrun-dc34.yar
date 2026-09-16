rule TTP_XOR_QUAD_CurrentVersionRun_dc34 {
  strings:
    $key_dc34 = { 8f 5b [2] ab 55 [2] 80 79 [2] ae 5b [2] ba 40 [2] b5 5a [2] ab 47 [2] a9 46 [2] b2 40 [2] ae 47 [2] b2 68 }

  condition:
    any of them
}