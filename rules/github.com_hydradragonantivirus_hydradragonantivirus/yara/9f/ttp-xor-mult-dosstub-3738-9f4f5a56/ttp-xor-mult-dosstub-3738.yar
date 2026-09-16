rule TTP_XOR_MULT_DOSStub_3738 {
  strings:
    $key_3738 = { 63 50 [2] 17 48 [2] 50 4a [2] 17 5b [2] 59 57 [2] 55 5d [2] 42 56 [2] 59 18 [2] 64 }

  condition:
    any of them
}