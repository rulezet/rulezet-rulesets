rule TTP_XOR_MULT_DOSStub_0a2c {
  strings:
    $key_0a2c = { 5e 44 [2] 2a 5c [2] 6d 5e [2] 2a 4f [2] 64 43 [2] 68 49 [2] 7f 42 [2] 64 0c [2] 59 }

  condition:
    any of them
}