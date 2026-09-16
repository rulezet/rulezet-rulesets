rule TTP_XOR_MULT_DOSStub_230c {
  strings:
    $key_230c = { 77 64 [2] 03 7c [2] 44 7e [2] 03 6f [2] 4d 63 [2] 41 69 [2] 56 62 [2] 4d 2c [2] 70 }

  condition:
    any of them
}