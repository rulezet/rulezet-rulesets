rule TTP_XOR_MULT_DOSStub_1964 {
  strings:
    $key_1964 = { 4d 0c [2] 39 14 [2] 7e 16 [2] 39 07 [2] 77 0b [2] 7b 01 [2] 6c 0a [2] 77 44 [2] 4a }

  condition:
    any of them
}