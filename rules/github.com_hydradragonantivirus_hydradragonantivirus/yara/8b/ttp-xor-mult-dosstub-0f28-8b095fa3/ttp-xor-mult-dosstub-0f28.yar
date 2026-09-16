rule TTP_XOR_MULT_DOSStub_0f28 {
  strings:
    $key_0f28 = { 5b 40 [2] 2f 58 [2] 68 5a [2] 2f 4b [2] 61 47 [2] 6d 4d [2] 7a 46 [2] 61 08 [2] 5c }

  condition:
    any of them
}