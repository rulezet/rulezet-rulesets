rule TTP_XOR_MULT_DOSStub_4b3c {
  strings:
    $key_4b3c = { 1f 54 [2] 6b 4c [2] 2c 4e [2] 6b 5f [2] 25 53 [2] 29 59 [2] 3e 52 [2] 25 1c [2] 18 }

  condition:
    any of them
}