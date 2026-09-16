rule TTP_XOR_MULT_DOSStub_191c {
  strings:
    $key_191c = { 4d 74 [2] 39 6c [2] 7e 6e [2] 39 7f [2] 77 73 [2] 7b 79 [2] 6c 72 [2] 77 3c [2] 4a }

  condition:
    any of them
}