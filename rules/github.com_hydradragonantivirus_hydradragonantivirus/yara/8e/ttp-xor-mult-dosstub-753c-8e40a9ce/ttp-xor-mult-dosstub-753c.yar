rule TTP_XOR_MULT_DOSStub_753c {
  strings:
    $key_753c = { 21 54 [2] 55 4c [2] 12 4e [2] 55 5f [2] 1b 53 [2] 17 59 [2] 00 52 [2] 1b 1c [2] 26 }

  condition:
    any of them
}