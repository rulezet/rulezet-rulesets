rule TTP_XOR_MULT_DOSStub_592c {
  strings:
    $key_592c = { 0d 44 [2] 79 5c [2] 3e 5e [2] 79 4f [2] 37 43 [2] 3b 49 [2] 2c 42 [2] 37 0c [2] 0a }

  condition:
    any of them
}