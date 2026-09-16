rule TTP_XOR_MULT_DOSStub_3538 {
  strings:
    $key_3538 = { 61 50 [2] 15 48 [2] 52 4a [2] 15 5b [2] 5b 57 [2] 57 5d [2] 40 56 [2] 5b 18 [2] 66 }

  condition:
    any of them
}