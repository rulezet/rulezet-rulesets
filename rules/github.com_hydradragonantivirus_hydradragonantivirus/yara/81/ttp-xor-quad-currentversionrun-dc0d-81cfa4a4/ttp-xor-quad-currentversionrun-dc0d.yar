rule TTP_XOR_QUAD_CurrentVersionRun_dc0d {
  strings:
    $key_dc0d = { 8f 62 [2] ab 6c [2] 80 40 [2] ae 62 [2] ba 79 [2] b5 63 [2] ab 7e [2] a9 7f [2] b2 79 [2] ae 7e [2] b2 51 }

  condition:
    any of them
}