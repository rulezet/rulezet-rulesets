rule TTP_XOR_MULT_DOSStub_0927 {
  strings:
    $key_0927 = { 5d 4f [2] 29 57 [2] 6e 55 [2] 29 44 [2] 67 48 [2] 6b 42 [2] 7c 49 [2] 67 07 [2] 5a }

  condition:
    any of them
}