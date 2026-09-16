rule TTP_XOR_QUAD_CurrentVersionRun_dc2c {
  strings:
    $key_dc2c = { 8f 43 [2] ab 4d [2] 80 61 [2] ae 43 [2] ba 58 [2] b5 42 [2] ab 5f [2] a9 5e [2] b2 58 [2] ae 5f [2] b2 70 }

  condition:
    any of them
}