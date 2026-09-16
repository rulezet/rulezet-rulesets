rule TTP_XOR_QUAD_CurrentVersionRun_dc26 {
  strings:
    $key_dc26 = { 8f 49 [2] ab 47 [2] 80 6b [2] ae 49 [2] ba 52 [2] b5 48 [2] ab 55 [2] a9 54 [2] b2 52 [2] ae 55 [2] b2 7a }

  condition:
    any of them
}