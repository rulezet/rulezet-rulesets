rule TTP_XOR_MULT_DOSStub_6317 {
  strings:
    $key_6317 = { 37 7f [2] 43 67 [2] 04 65 [2] 43 74 [2] 0d 78 [2] 01 72 [2] 16 79 [2] 0d 37 [2] 30 }

  condition:
    any of them
}