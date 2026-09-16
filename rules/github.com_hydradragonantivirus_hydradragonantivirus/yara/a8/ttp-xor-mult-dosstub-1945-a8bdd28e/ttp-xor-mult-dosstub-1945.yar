rule TTP_XOR_MULT_DOSStub_1945 {
  strings:
    $key_1945 = { 4d 2d [2] 39 35 [2] 7e 37 [2] 39 26 [2] 77 2a [2] 7b 20 [2] 6c 2b [2] 77 65 [2] 4a }

  condition:
    any of them
}