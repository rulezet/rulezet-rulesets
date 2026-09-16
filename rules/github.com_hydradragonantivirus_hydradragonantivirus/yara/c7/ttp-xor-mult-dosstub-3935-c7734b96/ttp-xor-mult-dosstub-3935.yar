rule TTP_XOR_MULT_DOSStub_3935 {
  strings:
    $key_3935 = { 6d 5d [2] 19 45 [2] 5e 47 [2] 19 56 [2] 57 5a [2] 5b 50 [2] 4c 5b [2] 57 15 [2] 6a }

  condition:
    any of them
}