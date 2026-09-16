rule TTP_XOR_MULT_DOSStub_2df4 {
  strings:
    $key_2df4 = { 79 9c [2] 0d 84 [2] 4a 86 [2] 0d 97 [2] 43 9b [2] 4f 91 [2] 58 9a [2] 43 d4 [2] 7e }

  condition:
    any of them
}