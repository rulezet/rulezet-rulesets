rule TTP_XOR_MULT_DOSStub_19e9 {
  strings:
    $key_19e9 = { 4d 81 [2] 39 99 [2] 7e 9b [2] 39 8a [2] 77 86 [2] 7b 8c [2] 6c 87 [2] 77 c9 [2] 4a }

  condition:
    any of them
}