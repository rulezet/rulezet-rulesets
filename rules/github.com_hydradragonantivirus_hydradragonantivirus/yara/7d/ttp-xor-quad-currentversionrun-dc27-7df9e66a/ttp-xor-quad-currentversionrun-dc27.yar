rule TTP_XOR_QUAD_CurrentVersionRun_dc27 {
  strings:
    $key_dc27 = { 8f 48 [2] ab 46 [2] 80 6a [2] ae 48 [2] ba 53 [2] b5 49 [2] ab 54 [2] a9 55 [2] b2 53 [2] ae 54 [2] b2 7b }

  condition:
    any of them
}