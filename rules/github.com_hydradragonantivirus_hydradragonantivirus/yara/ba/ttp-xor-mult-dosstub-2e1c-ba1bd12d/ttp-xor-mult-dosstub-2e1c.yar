rule TTP_XOR_MULT_DOSStub_2e1c {
  strings:
    $key_2e1c = { 7a 74 [2] 0e 6c [2] 49 6e [2] 0e 7f [2] 40 73 [2] 4c 79 [2] 5b 72 [2] 40 3c [2] 7d }

  condition:
    any of them
}