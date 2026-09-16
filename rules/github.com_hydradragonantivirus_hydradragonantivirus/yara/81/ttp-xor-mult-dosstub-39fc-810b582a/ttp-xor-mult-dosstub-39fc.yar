rule TTP_XOR_MULT_DOSStub_39fc {
  strings:
    $key_39fc = { 6d 94 [2] 19 8c [2] 5e 8e [2] 19 9f [2] 57 93 [2] 5b 99 [2] 4c 92 [2] 57 dc [2] 6a }

  condition:
    any of them
}