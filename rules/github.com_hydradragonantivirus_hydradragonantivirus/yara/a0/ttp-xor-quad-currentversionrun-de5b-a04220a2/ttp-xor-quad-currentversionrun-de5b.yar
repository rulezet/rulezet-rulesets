rule TTP_XOR_QUAD_CurrentVersionRun_de5b {
  strings:
    $key_de5b = { 8d 34 [2] a9 3a [2] 82 16 [2] ac 34 [2] b8 2f [2] b7 35 [2] a9 28 [2] ab 29 [2] b0 2f [2] ac 28 [2] b0 07 }

  condition:
    any of them
}