rule TTP_XOR_QUAD_CurrentVersionRun_de3f {
  strings:
    $key_de3f = { 8d 50 [2] a9 5e [2] 82 72 [2] ac 50 [2] b8 4b [2] b7 51 [2] a9 4c [2] ab 4d [2] b0 4b [2] ac 4c [2] b0 63 }

  condition:
    any of them
}