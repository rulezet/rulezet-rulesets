rule TTP_XOR_QUAD_CurrentVersionRun_c264 {
  strings:
    $key_c264 = { 91 0b [2] b5 05 [2] 9e 29 [2] b0 0b [2] a4 10 [2] ab 0a [2] b5 17 [2] b7 16 [2] ac 10 [2] b0 17 [2] ac 38 }

  condition:
    any of them
}