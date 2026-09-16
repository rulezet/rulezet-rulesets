rule TTP_XOR_QUAD_CurrentVersionRun_c204 {
  strings:
    $key_c204 = { 91 6b [2] b5 65 [2] 9e 49 [2] b0 6b [2] a4 70 [2] ab 6a [2] b5 77 [2] b7 76 [2] ac 70 [2] b0 77 [2] ac 58 }

  condition:
    any of them
}