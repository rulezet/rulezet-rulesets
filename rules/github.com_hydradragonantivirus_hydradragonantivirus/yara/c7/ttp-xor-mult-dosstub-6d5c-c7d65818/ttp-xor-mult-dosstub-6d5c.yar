rule TTP_XOR_MULT_DOSStub_6d5c {
  strings:
    $key_6d5c = { 39 34 [2] 4d 2c [2] 0a 2e [2] 4d 3f [2] 03 33 [2] 0f 39 [2] 18 32 [2] 03 7c [2] 3e }

  condition:
    any of them
}