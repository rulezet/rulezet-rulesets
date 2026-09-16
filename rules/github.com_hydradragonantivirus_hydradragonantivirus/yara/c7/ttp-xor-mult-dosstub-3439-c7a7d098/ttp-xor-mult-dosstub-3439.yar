rule TTP_XOR_MULT_DOSStub_3439 {
  strings:
    $key_3439 = { 60 51 [2] 14 49 [2] 53 4b [2] 14 5a [2] 5a 56 [2] 56 5c [2] 41 57 [2] 5a 19 [2] 67 }

  condition:
    any of them
}