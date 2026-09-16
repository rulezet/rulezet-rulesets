rule TTP_XOR_MULT_DOSStub_39f9 {
  strings:
    $key_39f9 = { 6d 91 [2] 19 89 [2] 5e 8b [2] 19 9a [2] 57 96 [2] 5b 9c [2] 4c 97 [2] 57 d9 [2] 6a }

  condition:
    any of them
}