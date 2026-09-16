rule TTP_XOR_MULT_DOSStub_4e3c {
  strings:
    $key_4e3c = { 1a 54 [2] 6e 4c [2] 29 4e [2] 6e 5f [2] 20 53 [2] 2c 59 [2] 3b 52 [2] 20 1c [2] 1d }

  condition:
    any of them
}