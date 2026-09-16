rule TTP_XOR_MULT_DOSStub_637c {
  strings:
    $key_637c = { 37 14 [2] 43 0c [2] 04 0e [2] 43 1f [2] 0d 13 [2] 01 19 [2] 16 12 [2] 0d 5c [2] 30 }

  condition:
    any of them
}