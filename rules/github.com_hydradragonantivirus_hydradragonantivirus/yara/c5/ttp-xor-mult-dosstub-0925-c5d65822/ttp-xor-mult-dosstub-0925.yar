rule TTP_XOR_MULT_DOSStub_0925 {
  strings:
    $key_0925 = { 5d 4d [2] 29 55 [2] 6e 57 [2] 29 46 [2] 67 4a [2] 6b 40 [2] 7c 4b [2] 67 05 [2] 5a }

  condition:
    any of them
}