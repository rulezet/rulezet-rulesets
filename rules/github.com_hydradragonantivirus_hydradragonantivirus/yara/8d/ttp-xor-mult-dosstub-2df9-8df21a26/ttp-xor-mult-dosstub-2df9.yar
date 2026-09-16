rule TTP_XOR_MULT_DOSStub_2df9 {
  strings:
    $key_2df9 = { 79 91 [2] 0d 89 [2] 4a 8b [2] 0d 9a [2] 43 96 [2] 4f 9c [2] 58 97 [2] 43 d9 [2] 7e }

  condition:
    any of them
}