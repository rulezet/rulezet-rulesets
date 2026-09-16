rule TTP_XOR_MULT_DOSStub_2a09 {
  strings:
    $key_2a09 = { 7e 61 [2] 0a 79 [2] 4d 7b [2] 0a 6a [2] 44 66 [2] 48 6c [2] 5f 67 [2] 44 29 [2] 79 }

  condition:
    any of them
}