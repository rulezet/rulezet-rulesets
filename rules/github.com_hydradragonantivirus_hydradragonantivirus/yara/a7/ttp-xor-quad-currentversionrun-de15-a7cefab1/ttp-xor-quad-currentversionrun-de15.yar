rule TTP_XOR_QUAD_CurrentVersionRun_de15 {
  strings:
    $key_de15 = { 8d 7a [2] a9 74 [2] 82 58 [2] ac 7a [2] b8 61 [2] b7 7b [2] a9 66 [2] ab 67 [2] b0 61 [2] ac 66 [2] b0 49 }

  condition:
    any of them
}