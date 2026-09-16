rule TTP_XOR_MULT_DOSStub_3f5c {
  strings:
    $key_3f5c = { 6b 34 [2] 1f 2c [2] 58 2e [2] 1f 3f [2] 51 33 [2] 5d 39 [2] 4a 32 [2] 51 7c [2] 6c }

  condition:
    any of them
}