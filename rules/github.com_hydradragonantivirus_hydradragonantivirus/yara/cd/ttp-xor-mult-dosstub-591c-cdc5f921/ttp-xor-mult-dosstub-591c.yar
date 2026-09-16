rule TTP_XOR_MULT_DOSStub_591c {
  strings:
    $key_591c = { 0d 74 [2] 79 6c [2] 3e 6e [2] 79 7f [2] 37 73 [2] 3b 79 [2] 2c 72 [2] 37 3c [2] 0a }

  condition:
    any of them
}