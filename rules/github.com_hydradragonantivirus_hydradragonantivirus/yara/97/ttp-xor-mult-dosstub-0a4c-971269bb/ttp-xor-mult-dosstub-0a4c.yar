rule TTP_XOR_MULT_DOSStub_0a4c {
  strings:
    $key_0a4c = { 5e 24 [2] 2a 3c [2] 6d 3e [2] 2a 2f [2] 64 23 [2] 68 29 [2] 7f 22 [2] 64 6c [2] 59 }

  condition:
    any of them
}