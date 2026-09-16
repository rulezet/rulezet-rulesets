rule TTP_XOR_MULT_DOSStub_3b5c {
  strings:
    $key_3b5c = { 6f 34 [2] 1b 2c [2] 5c 2e [2] 1b 3f [2] 55 33 [2] 59 39 [2] 4e 32 [2] 55 7c [2] 68 }

  condition:
    any of them
}