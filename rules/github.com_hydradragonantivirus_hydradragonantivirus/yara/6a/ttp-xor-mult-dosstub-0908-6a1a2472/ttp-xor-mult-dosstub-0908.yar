rule TTP_XOR_MULT_DOSStub_0908 {
  strings:
    $key_0908 = { 5d 60 [2] 29 78 [2] 6e 7a [2] 29 6b [2] 67 67 [2] 6b 6d [2] 7c 66 [2] 67 28 [2] 5a }

  condition:
    any of them
}