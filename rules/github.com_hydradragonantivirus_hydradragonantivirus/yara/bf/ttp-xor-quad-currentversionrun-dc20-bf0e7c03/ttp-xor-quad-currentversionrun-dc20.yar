rule TTP_XOR_QUAD_CurrentVersionRun_dc20 {
  strings:
    $key_dc20 = { 8f 4f [2] ab 41 [2] 80 6d [2] ae 4f [2] ba 54 [2] b5 4e [2] ab 53 [2] a9 52 [2] b2 54 [2] ae 53 [2] b2 7c }

  condition:
    any of them
}