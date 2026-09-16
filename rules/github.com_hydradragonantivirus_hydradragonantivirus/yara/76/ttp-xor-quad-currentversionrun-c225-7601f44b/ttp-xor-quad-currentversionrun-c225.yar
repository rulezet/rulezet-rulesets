rule TTP_XOR_QUAD_CurrentVersionRun_c225 {
  strings:
    $key_c225 = { 91 4a [2] b5 44 [2] 9e 68 [2] b0 4a [2] a4 51 [2] ab 4b [2] b5 56 [2] b7 57 [2] ac 51 [2] b0 56 [2] ac 79 }

  condition:
    any of them
}