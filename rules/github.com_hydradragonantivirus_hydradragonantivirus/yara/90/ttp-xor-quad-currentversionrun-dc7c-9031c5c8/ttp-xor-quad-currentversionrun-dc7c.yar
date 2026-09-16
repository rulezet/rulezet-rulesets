rule TTP_XOR_QUAD_CurrentVersionRun_dc7c {
  strings:
    $key_dc7c = { 8f 13 [2] ab 1d [2] 80 31 [2] ae 13 [2] ba 08 [2] b5 12 [2] ab 0f [2] a9 0e [2] b2 08 [2] ae 0f [2] b2 20 }

  condition:
    any of them
}