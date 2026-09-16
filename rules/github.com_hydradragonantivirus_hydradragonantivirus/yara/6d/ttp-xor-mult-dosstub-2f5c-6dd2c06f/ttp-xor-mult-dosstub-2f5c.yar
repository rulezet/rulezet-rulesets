rule TTP_XOR_MULT_DOSStub_2f5c {
  strings:
    $key_2f5c = { 7b 34 [2] 0f 2c [2] 48 2e [2] 0f 3f [2] 41 33 [2] 4d 39 [2] 5a 32 [2] 41 7c [2] 7c }

  condition:
    any of them
}