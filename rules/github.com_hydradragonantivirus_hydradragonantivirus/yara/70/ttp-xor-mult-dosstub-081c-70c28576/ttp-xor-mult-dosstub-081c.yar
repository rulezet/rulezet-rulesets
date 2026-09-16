rule TTP_XOR_MULT_DOSStub_081c {
  strings:
    $key_081c = { 5c 74 [2] 28 6c [2] 6f 6e [2] 28 7f [2] 66 73 [2] 6a 79 [2] 7d 72 [2] 66 3c [2] 5b }

  condition:
    any of them
}