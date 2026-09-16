rule TTP_XOR_QUAD_CurrentVersionRun_dce9 {
  strings:
    $key_dce9 = { 8f 86 [2] ab 88 [2] 80 a4 [2] ae 86 [2] ba 9d [2] b5 87 [2] ab 9a [2] a9 9b [2] b2 9d [2] ae 9a [2] b2 b5 }

  condition:
    any of them
}