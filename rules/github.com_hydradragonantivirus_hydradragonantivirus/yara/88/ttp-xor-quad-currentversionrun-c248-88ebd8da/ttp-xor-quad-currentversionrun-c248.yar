rule TTP_XOR_QUAD_CurrentVersionRun_c248 {
  strings:
    $key_c248 = { 91 27 [2] b5 29 [2] 9e 05 [2] b0 27 [2] a4 3c [2] ab 26 [2] b5 3b [2] b7 3a [2] ac 3c [2] b0 3b [2] ac 14 }

  condition:
    any of them
}