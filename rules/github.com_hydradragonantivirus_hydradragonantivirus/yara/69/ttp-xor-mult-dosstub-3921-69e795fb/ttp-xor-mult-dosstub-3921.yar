rule TTP_XOR_MULT_DOSStub_3921 {
  strings:
    $key_3921 = { 6d 49 [2] 19 51 [2] 5e 53 [2] 19 42 [2] 57 4e [2] 5b 44 [2] 4c 4f [2] 57 01 [2] 6a }

  condition:
    any of them
}