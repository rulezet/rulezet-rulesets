rule TTP_XOR_QUAD_CurrentVersionRun_c239 {
  strings:
    $key_c239 = { 91 56 [2] b5 58 [2] 9e 74 [2] b0 56 [2] a4 4d [2] ab 57 [2] b5 4a [2] b7 4b [2] ac 4d [2] b0 4a [2] ac 65 }

  condition:
    any of them
}