rule TTP_XOR_MULT_DOSStub_714c {
  strings:
    $key_714c = { 25 24 [2] 51 3c [2] 16 3e [2] 51 2f [2] 1f 23 [2] 13 29 [2] 04 22 [2] 1f 6c [2] 22 }

  condition:
    any of them
}