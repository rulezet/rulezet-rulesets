rule TTP_XOR_MULT_DOSStub_0135 {
  strings:
    $key_0135 = { 55 5d [2] 21 45 [2] 66 47 [2] 21 56 [2] 6f 5a [2] 63 50 [2] 74 5b [2] 6f 15 [2] 52 }

  condition:
    any of them
}