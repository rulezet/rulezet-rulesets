rule TTP_XOR_MULT_DOSStub_673c {
  strings:
    $key_673c = { 33 54 [2] 47 4c [2] 00 4e [2] 47 5f [2] 09 53 [2] 05 59 [2] 12 52 [2] 09 1c [2] 34 }

  condition:
    any of them
}