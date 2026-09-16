rule TTP_XOR_MULT_DOSStub_0924 {
  strings:
    $key_0924 = { 5d 4c [2] 29 54 [2] 6e 56 [2] 29 47 [2] 67 4b [2] 6b 41 [2] 7c 4a [2] 67 04 [2] 5a }

  condition:
    any of them
}