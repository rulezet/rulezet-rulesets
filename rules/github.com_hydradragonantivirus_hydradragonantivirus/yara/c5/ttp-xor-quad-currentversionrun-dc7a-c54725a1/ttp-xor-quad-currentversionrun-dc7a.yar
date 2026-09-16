rule TTP_XOR_QUAD_CurrentVersionRun_dc7a {
  strings:
    $key_dc7a = { 8f 15 [2] ab 1b [2] 80 37 [2] ae 15 [2] ba 0e [2] b5 14 [2] ab 09 [2] a9 08 [2] b2 0e [2] ae 09 [2] b2 26 }

  condition:
    any of them
}