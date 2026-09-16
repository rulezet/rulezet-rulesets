rule TTP_XOR_MULT_DOSStub_34e9 {
  strings:
    $key_34e9 = { 60 81 [2] 14 99 [2] 53 9b [2] 14 8a [2] 5a 86 [2] 56 8c [2] 41 87 [2] 5a c9 [2] 67 }

  condition:
    any of them
}