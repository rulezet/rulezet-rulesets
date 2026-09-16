rule TTP_XOR_MULT_DOSStub_7b7c {
  strings:
    $key_7b7c = { 2f 14 [2] 5b 0c [2] 1c 0e [2] 5b 1f [2] 15 13 [2] 19 19 [2] 0e 12 [2] 15 5c [2] 28 }

  condition:
    any of them
}