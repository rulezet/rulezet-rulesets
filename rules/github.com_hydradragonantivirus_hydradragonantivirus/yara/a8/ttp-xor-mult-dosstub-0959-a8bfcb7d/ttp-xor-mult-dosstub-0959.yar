rule TTP_XOR_MULT_DOSStub_0959 {
  strings:
    $key_0959 = { 5d 31 [2] 29 29 [2] 6e 2b [2] 29 3a [2] 67 36 [2] 6b 3c [2] 7c 37 [2] 67 79 [2] 5a }

  condition:
    any of them
}