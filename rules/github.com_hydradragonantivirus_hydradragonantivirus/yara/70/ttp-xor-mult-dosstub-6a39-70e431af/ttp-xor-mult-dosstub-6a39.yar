rule TTP_XOR_MULT_DOSStub_6a39 {
  strings:
    $key_6a39 = { 3e 51 [2] 4a 49 [2] 0d 4b [2] 4a 5a [2] 04 56 [2] 08 5c [2] 1f 57 [2] 04 19 [2] 39 }

  condition:
    any of them
}