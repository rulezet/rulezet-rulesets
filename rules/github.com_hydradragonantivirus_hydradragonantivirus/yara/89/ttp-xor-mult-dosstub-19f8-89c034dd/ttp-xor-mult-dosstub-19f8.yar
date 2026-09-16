rule TTP_XOR_MULT_DOSStub_19f8 {
  strings:
    $key_19f8 = { 4d 90 [2] 39 88 [2] 7e 8a [2] 39 9b [2] 77 97 [2] 7b 9d [2] 6c 96 [2] 77 d8 [2] 4a }

  condition:
    any of them
}