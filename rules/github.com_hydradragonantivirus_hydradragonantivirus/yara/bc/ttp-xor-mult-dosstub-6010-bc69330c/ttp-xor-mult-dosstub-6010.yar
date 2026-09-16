rule TTP_XOR_MULT_DOSStub_6010 {
  strings:
    $key_6010 = { 34 78 [2] 40 60 [2] 07 62 [2] 40 73 [2] 0e 7f [2] 02 75 [2] 15 7e [2] 0e 30 [2] 33 }

  condition:
    any of them
}