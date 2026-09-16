rule TTP_XOR_QUAD_CurrentVersionRun_c278 {
  strings:
    $key_c278 = { 91 17 [2] b5 19 [2] 9e 35 [2] b0 17 [2] a4 0c [2] ab 16 [2] b5 0b [2] b7 0a [2] ac 0c [2] b0 0b [2] ac 24 }

  condition:
    any of them
}