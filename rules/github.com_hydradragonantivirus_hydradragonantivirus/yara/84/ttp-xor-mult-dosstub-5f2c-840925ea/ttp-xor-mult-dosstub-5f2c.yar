rule TTP_XOR_MULT_DOSStub_5f2c {
  strings:
    $key_5f2c = { 0b 44 [2] 7f 5c [2] 38 5e [2] 7f 4f [2] 31 43 [2] 3d 49 [2] 2a 42 [2] 31 0c [2] 0c }

  condition:
    any of them
}