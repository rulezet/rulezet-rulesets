rule TTP_XOR_MULT_DOSStub_0f25 {
  strings:
    $key_0f25 = { 5b 4d [2] 2f 55 [2] 68 57 [2] 2f 46 [2] 61 4a [2] 6d 40 [2] 7a 4b [2] 61 05 [2] 5c }

  condition:
    any of them
}