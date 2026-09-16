rule TTP_XOR_MULT_DOSStub_7639 {
  strings:
    $key_7639 = { 22 51 [2] 56 49 [2] 11 4b [2] 56 5a [2] 18 56 [2] 14 5c [2] 03 57 [2] 18 19 [2] 25 }

  condition:
    any of them
}