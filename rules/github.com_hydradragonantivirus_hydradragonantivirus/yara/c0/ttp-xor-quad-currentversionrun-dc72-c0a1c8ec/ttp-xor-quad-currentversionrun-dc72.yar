rule TTP_XOR_QUAD_CurrentVersionRun_dc72 {
  strings:
    $key_dc72 = { 8f 1d [2] ab 13 [2] 80 3f [2] ae 1d [2] ba 06 [2] b5 1c [2] ab 01 [2] a9 00 [2] b2 06 [2] ae 01 [2] b2 2e }

  condition:
    any of them
}