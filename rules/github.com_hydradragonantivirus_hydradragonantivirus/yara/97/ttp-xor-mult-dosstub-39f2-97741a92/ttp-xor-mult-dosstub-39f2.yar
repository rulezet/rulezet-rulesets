rule TTP_XOR_MULT_DOSStub_39f2 {
  strings:
    $key_39f2 = { 6d 9a [2] 19 82 [2] 5e 80 [2] 19 91 [2] 57 9d [2] 5b 97 [2] 4c 9c [2] 57 d2 [2] 6a }

  condition:
    any of them
}