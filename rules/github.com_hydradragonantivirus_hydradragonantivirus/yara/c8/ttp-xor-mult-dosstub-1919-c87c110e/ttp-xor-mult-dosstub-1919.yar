rule TTP_XOR_MULT_DOSStub_1919 {
  strings:
    $key_1919 = { 4d 71 [2] 39 69 [2] 7e 6b [2] 39 7a [2] 77 76 [2] 7b 7c [2] 6c 77 [2] 77 39 [2] 4a }

  condition:
    any of them
}