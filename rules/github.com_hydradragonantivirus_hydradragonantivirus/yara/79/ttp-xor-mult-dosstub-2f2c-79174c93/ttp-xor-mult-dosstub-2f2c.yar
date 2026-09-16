rule TTP_XOR_MULT_DOSStub_2f2c {
  strings:
    $key_2f2c = { 7b 44 [2] 0f 5c [2] 48 5e [2] 0f 4f [2] 41 43 [2] 4d 49 [2] 5a 42 [2] 41 0c [2] 7c }

  condition:
    any of them
}