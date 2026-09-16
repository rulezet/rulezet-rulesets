rule TTP_XOR_QUAD_CurrentVersionRun_dc2f {
  strings:
    $key_dc2f = { 8f 40 [2] ab 4e [2] 80 62 [2] ae 40 [2] ba 5b [2] b5 41 [2] ab 5c [2] a9 5d [2] b2 5b [2] ae 5c [2] b2 73 }

  condition:
    any of them
}