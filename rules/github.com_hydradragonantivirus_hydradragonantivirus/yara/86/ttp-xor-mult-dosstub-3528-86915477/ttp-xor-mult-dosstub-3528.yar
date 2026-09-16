rule TTP_XOR_MULT_DOSStub_3528 {
  strings:
    $key_3528 = { 61 40 [2] 15 58 [2] 52 5a [2] 15 4b [2] 5b 47 [2] 57 4d [2] 40 46 [2] 5b 08 [2] 66 }

  condition:
    any of them
}