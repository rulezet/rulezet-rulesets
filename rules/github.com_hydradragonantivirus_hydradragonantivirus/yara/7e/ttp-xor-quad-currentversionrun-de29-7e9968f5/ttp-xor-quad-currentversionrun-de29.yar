rule TTP_XOR_QUAD_CurrentVersionRun_de29 {
  strings:
    $key_de29 = { 8d 46 [2] a9 48 [2] 82 64 [2] ac 46 [2] b8 5d [2] b7 47 [2] a9 5a [2] ab 5b [2] b0 5d [2] ac 5a [2] b0 75 }

  condition:
    any of them
}