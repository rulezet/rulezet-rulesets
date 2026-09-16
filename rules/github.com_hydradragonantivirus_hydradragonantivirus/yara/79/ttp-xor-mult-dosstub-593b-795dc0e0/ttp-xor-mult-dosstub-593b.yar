rule TTP_XOR_MULT_DOSStub_593b {
  strings:
    $key_593b = { 0d 53 [2] 79 4b [2] 3e 49 [2] 79 58 [2] 37 54 [2] 3b 5e [2] 2c 55 [2] 37 1b [2] 0a }

  condition:
    any of them
}