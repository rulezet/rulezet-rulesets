rule TTP_XOR_QUAD_CurrentVersionRun_de59 {
  strings:
    $key_de59 = { 8d 36 [2] a9 38 [2] 82 14 [2] ac 36 [2] b8 2d [2] b7 37 [2] a9 2a [2] ab 2b [2] b0 2d [2] ac 2a [2] b0 05 }

  condition:
    any of them
}