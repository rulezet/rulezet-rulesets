rule TTP_XOR_MULT_DOSStub_3405 {
  strings:
    $key_3405 = { 60 6d [2] 14 75 [2] 53 77 [2] 14 66 [2] 5a 6a [2] 56 60 [2] 41 6b [2] 5a 25 [2] 67 }

  condition:
    any of them
}