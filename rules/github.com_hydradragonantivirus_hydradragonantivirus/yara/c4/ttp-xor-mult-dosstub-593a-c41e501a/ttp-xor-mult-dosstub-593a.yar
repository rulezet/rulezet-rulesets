rule TTP_XOR_MULT_DOSStub_593a {
  strings:
    $key_593a = { 0d 52 [2] 79 4a [2] 3e 48 [2] 79 59 [2] 37 55 [2] 3b 5f [2] 2c 54 [2] 37 1a [2] 0a }

  condition:
    any of them
}