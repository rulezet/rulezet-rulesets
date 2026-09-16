rule TTP_XOR_MULT_DOSStub_3404 {
  strings:
    $key_3404 = { 60 6c [2] 14 74 [2] 53 76 [2] 14 67 [2] 5a 6b [2] 56 61 [2] 41 6a [2] 5a 24 [2] 67 }

  condition:
    any of them
}