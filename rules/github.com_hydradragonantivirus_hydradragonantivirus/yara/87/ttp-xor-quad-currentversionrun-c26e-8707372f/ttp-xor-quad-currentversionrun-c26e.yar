rule TTP_XOR_QUAD_CurrentVersionRun_c26e {
  strings:
    $key_c26e = { 91 01 [2] b5 0f [2] 9e 23 [2] b0 01 [2] a4 1a [2] ab 00 [2] b5 1d [2] b7 1c [2] ac 1a [2] b0 1d [2] ac 32 }

  condition:
    any of them
}