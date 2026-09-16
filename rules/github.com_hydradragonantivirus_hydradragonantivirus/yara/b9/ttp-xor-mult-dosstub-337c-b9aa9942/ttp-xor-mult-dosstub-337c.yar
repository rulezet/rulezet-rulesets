rule TTP_XOR_MULT_DOSStub_337c {
  strings:
    $key_337c = { 67 14 [2] 13 0c [2] 54 0e [2] 13 1f [2] 5d 13 [2] 51 19 [2] 46 12 [2] 5d 5c [2] 60 }

  condition:
    any of them
}