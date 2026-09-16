rule TTP_XOR_MULT_DOSStub_3de5 {
  strings:
    $key_3de5 = { 69 8d [2] 1d 95 [2] 5a 97 [2] 1d 86 [2] 53 8a [2] 5f 80 [2] 48 8b [2] 53 c5 [2] 6e }

  condition:
    any of them
}