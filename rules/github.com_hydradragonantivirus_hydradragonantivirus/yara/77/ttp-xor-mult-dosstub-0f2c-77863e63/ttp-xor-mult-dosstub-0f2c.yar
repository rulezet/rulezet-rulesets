rule TTP_XOR_MULT_DOSStub_0f2c {
  strings:
    $key_0f2c = { 5b 44 [2] 2f 5c [2] 68 5e [2] 2f 4f [2] 61 43 [2] 6d 49 [2] 7a 42 [2] 61 0c [2] 5c }

  condition:
    any of them
}