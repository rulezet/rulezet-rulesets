rule TTP_XOR_MULT_DOSStub_7f3c {
  strings:
    $key_7f3c = { 2b 54 [2] 5f 4c [2] 18 4e [2] 5f 5f [2] 11 53 [2] 1d 59 [2] 0a 52 [2] 11 1c [2] 2c }

  condition:
    any of them
}