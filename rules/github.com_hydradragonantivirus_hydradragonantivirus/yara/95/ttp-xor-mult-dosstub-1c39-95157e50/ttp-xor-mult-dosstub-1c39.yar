rule TTP_XOR_MULT_DOSStub_1c39 {
  strings:
    $key_1c39 = { 48 51 [2] 3c 49 [2] 7b 4b [2] 3c 5a [2] 72 56 [2] 7e 5c [2] 69 57 [2] 72 19 [2] 4f }

  condition:
    any of them
}