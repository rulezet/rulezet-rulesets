rule TTP_XOR_QUAD_CurrentVersionRun_de3c {
  strings:
    $key_de3c = { 8d 53 [2] a9 5d [2] 82 71 [2] ac 53 [2] b8 48 [2] b7 52 [2] a9 4f [2] ab 4e [2] b0 48 [2] ac 4f [2] b0 60 }

  condition:
    any of them
}