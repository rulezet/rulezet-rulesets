rule TTP_XOR_QUAD_CurrentVersionRun_c205 {
  strings:
    $key_c205 = { 91 6a [2] b5 64 [2] 9e 48 [2] b0 6a [2] a4 71 [2] ab 6b [2] b5 76 [2] b7 77 [2] ac 71 [2] b0 76 [2] ac 59 }

  condition:
    any of them
}