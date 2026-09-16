rule TTP_XOR_QUAD_CurrentVersionRun_c209 {
  strings:
    $key_c209 = { 91 66 [2] b5 68 [2] 9e 44 [2] b0 66 [2] a4 7d [2] ab 67 [2] b5 7a [2] b7 7b [2] ac 7d [2] b0 7a [2] ac 55 }

  condition:
    any of them
}