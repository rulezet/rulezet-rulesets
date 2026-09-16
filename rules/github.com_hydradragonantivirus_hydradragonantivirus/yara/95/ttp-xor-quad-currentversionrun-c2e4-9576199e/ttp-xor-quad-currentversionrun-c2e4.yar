rule TTP_XOR_QUAD_CurrentVersionRun_c2e4 {
  strings:
    $key_c2e4 = { 91 8b [2] b5 85 [2] 9e a9 [2] b0 8b [2] a4 90 [2] ab 8a [2] b5 97 [2] b7 96 [2] ac 90 [2] b0 97 [2] ac b8 }

  condition:
    any of them
}