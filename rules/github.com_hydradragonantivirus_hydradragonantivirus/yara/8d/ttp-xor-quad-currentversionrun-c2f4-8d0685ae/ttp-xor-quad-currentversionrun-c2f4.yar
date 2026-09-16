rule TTP_XOR_QUAD_CurrentVersionRun_c2f4 {
  strings:
    $key_c2f4 = { 91 9b [2] b5 95 [2] 9e b9 [2] b0 9b [2] a4 80 [2] ab 9a [2] b5 87 [2] b7 86 [2] ac 80 [2] b0 87 [2] ac a8 }

  condition:
    any of them
}