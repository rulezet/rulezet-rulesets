rule TTP_XOR_MULT_DOSStub_3927 {
  strings:
    $key_3927 = { 6d 4f [2] 19 57 [2] 5e 55 [2] 19 44 [2] 57 48 [2] 5b 42 [2] 4c 49 [2] 57 07 [2] 6a }

  condition:
    any of them
}