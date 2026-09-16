rule TTP_XOR_QUAD_CurrentVersionRun_c255 {
  strings:
    $key_c255 = { 91 3a [2] b5 34 [2] 9e 18 [2] b0 3a [2] a4 21 [2] ab 3b [2] b5 26 [2] b7 27 [2] ac 21 [2] b0 26 [2] ac 09 }

  condition:
    any of them
}