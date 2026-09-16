rule TTP_XOR_QUAD_CurrentVersionRun_c274 {
  strings:
    $key_c274 = { 91 1b [2] b5 15 [2] 9e 39 [2] b0 1b [2] a4 00 [2] ab 1a [2] b5 07 [2] b7 06 [2] ac 00 [2] b0 07 [2] ac 28 }

  condition:
    any of them
}