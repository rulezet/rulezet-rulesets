rule TTP_XOR_MULT_DOSStub_34f8 {
  strings:
    $key_34f8 = { 60 90 [2] 14 88 [2] 53 8a [2] 14 9b [2] 5a 97 [2] 56 9d [2] 41 96 [2] 5a d8 [2] 67 }

  condition:
    any of them
}