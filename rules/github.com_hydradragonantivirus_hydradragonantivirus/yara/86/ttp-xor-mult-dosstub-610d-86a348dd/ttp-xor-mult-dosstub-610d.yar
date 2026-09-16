rule TTP_XOR_MULT_DOSStub_610d {
  strings:
    $key_610d = { 35 65 [2] 41 7d [2] 06 7f [2] 41 6e [2] 0f 62 [2] 03 68 [2] 14 63 [2] 0f 2d [2] 32 }

  condition:
    any of them
}