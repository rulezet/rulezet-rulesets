rule TTP_XOR_MULT_DOSStub_19f5 {
  strings:
    $key_19f5 = { 4d 9d [2] 39 85 [2] 7e 87 [2] 39 96 [2] 77 9a [2] 7b 90 [2] 6c 9b [2] 77 d5 [2] 4a }

  condition:
    any of them
}