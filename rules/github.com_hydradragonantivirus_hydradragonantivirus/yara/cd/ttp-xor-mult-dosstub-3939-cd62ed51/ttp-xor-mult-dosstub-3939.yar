rule TTP_XOR_MULT_DOSStub_3939 {
  strings:
    $key_3939 = { 6d 51 [2] 19 49 [2] 5e 4b [2] 19 5a [2] 57 56 [2] 5b 5c [2] 4c 57 [2] 57 19 [2] 6a }

  condition:
    any of them
}