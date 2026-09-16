rule TTP_XOR_QUAD_CurrentVersionRun_c57f {
  strings:
    $key_c57f = { 96 10 [2] b2 1e [2] 99 32 [2] b7 10 [2] a3 0b [2] ac 11 [2] b2 0c [2] b0 0d [2] ab 0b [2] b7 0c [2] ab 23 }

  condition:
    any of them
}