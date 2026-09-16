rule TTP_XOR_QUAD_CurrentVersionRun_de24 {
  strings:
    $key_de24 = { 8d 4b [2] a9 45 [2] 82 69 [2] ac 4b [2] b8 50 [2] b7 4a [2] a9 57 [2] ab 56 [2] b0 50 [2] ac 57 [2] b0 78 }

  condition:
    any of them
}