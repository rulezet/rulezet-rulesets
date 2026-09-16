rule TTP_XOR_MULT_DOSStub_593d {
  strings:
    $key_593d = { 0d 55 [2] 79 4d [2] 3e 4f [2] 79 5e [2] 37 52 [2] 3b 58 [2] 2c 53 [2] 37 1d [2] 0a }

  condition:
    any of them
}