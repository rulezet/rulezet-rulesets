rule TTP_XOR_QUAD_CurrentVersionRun_de0e {
  strings:
    $key_de0e = { 8d 61 [2] a9 6f [2] 82 43 [2] ac 61 [2] b8 7a [2] b7 60 [2] a9 7d [2] ab 7c [2] b0 7a [2] ac 7d [2] b0 52 }

  condition:
    any of them
}