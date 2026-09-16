rule TTP_XOR_MULT_DOSStub_6a38 {
  strings:
    $key_6a38 = { 3e 50 [2] 4a 48 [2] 0d 4a [2] 4a 5b [2] 04 57 [2] 08 5d [2] 1f 56 [2] 04 18 [2] 39 }

  condition:
    any of them
}