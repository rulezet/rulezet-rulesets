rule TTP_XOR_MULT_DOSStub_f043 {
  strings:
    $key_f043 = { a4 2b [2] d0 33 [2] 97 31 [2] d0 20 [2] 9e 2c [2] 92 26 [2] 85 2d [2] 9e 63 [2] a3 }

  condition:
    any of them
}