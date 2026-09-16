rule TTP_XOR_QUAD_CurrentVersionRun_c27f {
  strings:
    $key_c27f = { 91 10 [2] b5 1e [2] 9e 32 [2] b0 10 [2] a4 0b [2] ab 11 [2] b5 0c [2] b7 0d [2] ac 0b [2] b0 0c [2] ac 23 }

  condition:
    any of them
}