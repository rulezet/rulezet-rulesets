rule TTP_XOR_MULT_DOSStub_517c {
  strings:
    $key_517c = { 05 14 [2] 71 0c [2] 36 0e [2] 71 1f [2] 3f 13 [2] 33 19 [2] 24 12 [2] 3f 5c [2] 02 }

  condition:
    any of them
}