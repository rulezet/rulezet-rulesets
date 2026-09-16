rule TTP_XOR_QUAD_CurrentVersionRun_de04 {
  strings:
    $key_de04 = { 8d 6b [2] a9 65 [2] 82 49 [2] ac 6b [2] b8 70 [2] b7 6a [2] a9 77 [2] ab 76 [2] b0 70 [2] ac 77 [2] b0 58 }

  condition:
    any of them
}