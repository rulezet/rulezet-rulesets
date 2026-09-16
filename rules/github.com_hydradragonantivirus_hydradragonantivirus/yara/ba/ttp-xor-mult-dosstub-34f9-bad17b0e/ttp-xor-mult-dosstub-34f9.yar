rule TTP_XOR_MULT_DOSStub_34f9 {
  strings:
    $key_34f9 = { 60 91 [2] 14 89 [2] 53 8b [2] 14 9a [2] 5a 96 [2] 56 9c [2] 41 97 [2] 5a d9 [2] 67 }

  condition:
    any of them
}