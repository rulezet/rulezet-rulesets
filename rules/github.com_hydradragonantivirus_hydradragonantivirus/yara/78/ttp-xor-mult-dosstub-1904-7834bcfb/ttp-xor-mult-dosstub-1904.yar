rule TTP_XOR_MULT_DOSStub_1904 {
  strings:
    $key_1904 = { 4d 6c [2] 39 74 [2] 7e 76 [2] 39 67 [2] 77 6b [2] 7b 61 [2] 6c 6a [2] 77 24 [2] 4a }

  condition:
    any of them
}