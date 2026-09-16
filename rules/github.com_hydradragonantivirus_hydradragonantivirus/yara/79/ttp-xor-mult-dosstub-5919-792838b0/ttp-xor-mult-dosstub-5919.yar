rule TTP_XOR_MULT_DOSStub_5919 {
  strings:
    $key_5919 = { 0d 71 [2] 79 69 [2] 3e 6b [2] 79 7a [2] 37 76 [2] 3b 7c [2] 2c 77 [2] 37 39 [2] 0a }

  condition:
    any of them
}