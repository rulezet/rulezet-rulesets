rule TTP_XOR_QUAD_CurrentVersionRun_de79 {
  strings:
    $key_de79 = { 8d 16 [2] a9 18 [2] 82 34 [2] ac 16 [2] b8 0d [2] b7 17 [2] a9 0a [2] ab 0b [2] b0 0d [2] ac 0a [2] b0 25 }

  condition:
    any of them
}