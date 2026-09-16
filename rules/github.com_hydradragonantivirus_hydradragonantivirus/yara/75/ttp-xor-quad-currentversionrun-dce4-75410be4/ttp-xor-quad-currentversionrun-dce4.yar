rule TTP_XOR_QUAD_CurrentVersionRun_dce4 {
  strings:
    $key_dce4 = { 8f 8b [2] ab 85 [2] 80 a9 [2] ae 8b [2] ba 90 [2] b5 8a [2] ab 97 [2] a9 96 [2] b2 90 [2] ae 97 [2] b2 b8 }

  condition:
    any of them
}