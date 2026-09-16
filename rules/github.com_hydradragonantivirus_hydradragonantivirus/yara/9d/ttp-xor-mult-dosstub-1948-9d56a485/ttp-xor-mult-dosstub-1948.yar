rule TTP_XOR_MULT_DOSStub_1948 {
  strings:
    $key_1948 = { 4d 20 [2] 39 38 [2] 7e 3a [2] 39 2b [2] 77 27 [2] 7b 2d [2] 6c 26 [2] 77 68 [2] 4a }

  condition:
    any of them
}