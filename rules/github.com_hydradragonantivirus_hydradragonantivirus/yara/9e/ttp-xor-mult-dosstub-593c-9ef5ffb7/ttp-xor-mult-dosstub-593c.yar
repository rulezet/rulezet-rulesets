rule TTP_XOR_MULT_DOSStub_593c {
  strings:
    $key_593c = { 0d 54 [2] 79 4c [2] 3e 4e [2] 79 5f [2] 37 53 [2] 3b 59 [2] 2c 52 [2] 37 1c [2] 0a }

  condition:
    any of them
}