rule TTP_XOR_MULT_DOSStub_1978 {
  strings:
    $key_1978 = { 4d 10 [2] 39 08 [2] 7e 0a [2] 39 1b [2] 77 17 [2] 7b 1d [2] 6c 16 [2] 77 58 [2] 4a }

  condition:
    any of them
}