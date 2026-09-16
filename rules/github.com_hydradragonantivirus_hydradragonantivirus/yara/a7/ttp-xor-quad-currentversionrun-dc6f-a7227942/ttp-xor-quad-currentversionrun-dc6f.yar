rule TTP_XOR_QUAD_CurrentVersionRun_dc6f {
  strings:
    $key_dc6f = { 8f 00 [2] ab 0e [2] 80 22 [2] ae 00 [2] ba 1b [2] b5 01 [2] ab 1c [2] a9 1d [2] b2 1b [2] ae 1c [2] b2 33 }

  condition:
    any of them
}