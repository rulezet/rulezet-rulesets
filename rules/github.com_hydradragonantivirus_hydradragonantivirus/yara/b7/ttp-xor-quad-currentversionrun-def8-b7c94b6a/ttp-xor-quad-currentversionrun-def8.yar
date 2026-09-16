rule TTP_XOR_QUAD_CurrentVersionRun_def8 {
  strings:
    $key_def8 = { 8d 97 [2] a9 99 [2] 82 b5 [2] ac 97 [2] b8 8c [2] b7 96 [2] a9 8b [2] ab 8a [2] b0 8c [2] ac 8b [2] b0 a4 }

  condition:
    any of them
}