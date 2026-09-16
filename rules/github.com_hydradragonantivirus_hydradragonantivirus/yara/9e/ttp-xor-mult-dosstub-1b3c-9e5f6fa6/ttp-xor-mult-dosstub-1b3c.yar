rule TTP_XOR_MULT_DOSStub_1b3c {
  strings:
    $key_1b3c = { 4f 54 [2] 3b 4c [2] 7c 4e [2] 3b 5f [2] 75 53 [2] 79 59 [2] 6e 52 [2] 75 1c [2] 48 }

  condition:
    any of them
}