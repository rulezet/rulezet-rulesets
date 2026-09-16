rule TTP_XOR_MULT_DOSStub_737c {
  strings:
    $key_737c = { 27 14 [2] 53 0c [2] 14 0e [2] 53 1f [2] 1d 13 [2] 11 19 [2] 06 12 [2] 1d 5c [2] 20 }

  condition:
    any of them
}