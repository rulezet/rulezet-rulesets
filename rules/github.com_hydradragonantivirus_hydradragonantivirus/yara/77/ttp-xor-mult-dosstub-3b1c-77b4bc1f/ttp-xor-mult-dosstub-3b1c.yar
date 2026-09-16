rule TTP_XOR_MULT_DOSStub_3b1c {
  strings:
    $key_3b1c = { 6f 74 [2] 1b 6c [2] 5c 6e [2] 1b 7f [2] 55 73 [2] 59 79 [2] 4e 72 [2] 55 3c [2] 68 }

  condition:
    any of them
}