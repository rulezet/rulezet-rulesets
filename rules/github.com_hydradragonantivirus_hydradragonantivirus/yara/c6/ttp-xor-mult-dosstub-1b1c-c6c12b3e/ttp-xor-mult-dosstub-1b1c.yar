rule TTP_XOR_MULT_DOSStub_1b1c {
  strings:
    $key_1b1c = { 4f 74 [2] 3b 6c [2] 7c 6e [2] 3b 7f [2] 75 73 [2] 79 79 [2] 6e 72 [2] 75 3c [2] 48 }

  condition:
    any of them
}