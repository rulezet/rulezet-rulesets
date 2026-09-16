rule TTP_XOR_MULT_DOSStub_34e5 {
  strings:
    $key_34e5 = { 60 8d [2] 14 95 [2] 53 97 [2] 14 86 [2] 5a 8a [2] 56 80 [2] 41 8b [2] 5a c5 [2] 67 }

  condition:
    any of them
}