rule TTP_XOR_MULT_DOSStub_2b5c {
  strings:
    $key_2b5c = { 7f 34 [2] 0b 2c [2] 4c 2e [2] 0b 3f [2] 45 33 [2] 49 39 [2] 5e 32 [2] 45 7c [2] 78 }

  condition:
    any of them
}