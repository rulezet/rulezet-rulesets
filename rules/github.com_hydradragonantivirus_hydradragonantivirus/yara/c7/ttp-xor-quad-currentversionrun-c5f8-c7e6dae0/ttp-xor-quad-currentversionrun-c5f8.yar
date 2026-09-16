rule TTP_XOR_QUAD_CurrentVersionRun_c5f8 {
  strings:
    $key_c5f8 = { 96 97 [2] b2 99 [2] 99 b5 [2] b7 97 [2] a3 8c [2] ac 96 [2] b2 8b [2] b0 8a [2] ab 8c [2] b7 8b [2] ab a4 }

  condition:
    any of them
}