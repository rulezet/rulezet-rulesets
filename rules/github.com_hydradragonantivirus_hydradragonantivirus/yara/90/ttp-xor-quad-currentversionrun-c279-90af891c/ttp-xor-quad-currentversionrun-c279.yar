rule TTP_XOR_QUAD_CurrentVersionRun_c279 {
  strings:
    $key_c279 = { 91 16 [2] b5 18 [2] 9e 34 [2] b0 16 [2] a4 0d [2] ab 17 [2] b5 0a [2] b7 0b [2] ac 0d [2] b0 0a [2] ac 25 }

  condition:
    any of them
}