rule TTP_XOR_QUAD_CurrentVersionRun_de2e {
  strings:
    $key_de2e = { 8d 41 [2] a9 4f [2] 82 63 [2] ac 41 [2] b8 5a [2] b7 40 [2] a9 5d [2] ab 5c [2] b0 5a [2] ac 5d [2] b0 72 }

  condition:
    any of them
}