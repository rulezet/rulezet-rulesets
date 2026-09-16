rule TTP_XOR_MULT_DOSStub_34f2 {
  strings:
    $key_34f2 = { 60 9a [2] 14 82 [2] 53 80 [2] 14 91 [2] 5a 9d [2] 56 97 [2] 41 9c [2] 5a d2 [2] 67 }

  condition:
    any of them
}