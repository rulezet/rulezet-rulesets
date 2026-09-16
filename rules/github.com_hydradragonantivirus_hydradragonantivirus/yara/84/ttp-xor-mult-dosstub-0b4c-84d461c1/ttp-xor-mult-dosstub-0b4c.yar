rule TTP_XOR_MULT_DOSStub_0b4c {
  strings:
    $key_0b4c = { 5f 24 [2] 2b 3c [2] 6c 3e [2] 2b 2f [2] 65 23 [2] 69 29 [2] 7e 22 [2] 65 6c [2] 58 }

  condition:
    any of them
}