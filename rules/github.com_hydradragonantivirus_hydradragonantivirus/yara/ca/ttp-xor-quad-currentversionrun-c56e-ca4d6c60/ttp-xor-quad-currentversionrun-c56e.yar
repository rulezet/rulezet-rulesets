rule TTP_XOR_QUAD_CurrentVersionRun_c56e {
  strings:
    $key_c56e = { 96 01 [2] b2 0f [2] 99 23 [2] b7 01 [2] a3 1a [2] ac 00 [2] b2 1d [2] b0 1c [2] ab 1a [2] b7 1d [2] ab 32 }

  condition:
    any of them
}