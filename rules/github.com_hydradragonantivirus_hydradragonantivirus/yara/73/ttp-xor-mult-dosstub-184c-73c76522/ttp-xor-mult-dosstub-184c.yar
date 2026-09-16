rule TTP_XOR_MULT_DOSStub_184c {
  strings:
    $key_184c = { 4c 24 [2] 38 3c [2] 7f 3e [2] 38 2f [2] 76 23 [2] 7a 29 [2] 6d 22 [2] 76 6c [2] 4b }

  condition:
    any of them
}