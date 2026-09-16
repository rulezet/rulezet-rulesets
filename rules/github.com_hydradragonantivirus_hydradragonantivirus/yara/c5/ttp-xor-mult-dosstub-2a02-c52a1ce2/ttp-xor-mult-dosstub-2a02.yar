rule TTP_XOR_MULT_DOSStub_2a02 {
  strings:
    $key_2a02 = { 7e 6a [2] 0a 72 [2] 4d 70 [2] 0a 61 [2] 44 6d [2] 48 67 [2] 5f 6c [2] 44 22 [2] 79 }

  condition:
    any of them
}