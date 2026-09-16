rule TTP_XOR_QUAD_CurrentVersionRun_dc1b {
  strings:
    $key_dc1b = { 8f 74 [2] ab 7a [2] 80 56 [2] ae 74 [2] ba 6f [2] b5 75 [2] ab 68 [2] a9 69 [2] b2 6f [2] ae 68 [2] b2 47 }

  condition:
    any of them
}