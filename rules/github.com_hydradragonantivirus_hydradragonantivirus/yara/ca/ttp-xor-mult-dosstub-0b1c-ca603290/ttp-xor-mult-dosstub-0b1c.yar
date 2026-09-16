rule TTP_XOR_MULT_DOSStub_0b1c {
  strings:
    $key_0b1c = { 5f 74 [2] 2b 6c [2] 6c 6e [2] 2b 7f [2] 65 73 [2] 69 79 [2] 7e 72 [2] 65 3c [2] 58 }

  condition:
    any of them
}