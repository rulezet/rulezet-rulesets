rule TTP_XOR_MULT_DOSStub_34e8 {
  strings:
    $key_34e8 = { 60 80 [2] 14 98 [2] 53 9a [2] 14 8b [2] 5a 87 [2] 56 8d [2] 41 86 [2] 5a c8 [2] 67 }

  condition:
    any of them
}