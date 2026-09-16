rule TTP_XOR_MULT_DOSStub_093c {
  strings:
    $key_093c = { 5d 54 [2] 29 4c [2] 6e 4e [2] 29 5f [2] 67 53 [2] 6b 59 [2] 7c 52 [2] 67 1c [2] 5a }

  condition:
    any of them
}