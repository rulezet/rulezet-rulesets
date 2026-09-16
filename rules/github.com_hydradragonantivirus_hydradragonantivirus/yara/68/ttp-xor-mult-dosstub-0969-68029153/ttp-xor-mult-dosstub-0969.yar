rule TTP_XOR_MULT_DOSStub_0969 {
  strings:
    $key_0969 = { 5d 01 [2] 29 19 [2] 6e 1b [2] 29 0a [2] 67 06 [2] 6b 0c [2] 7c 07 [2] 67 49 [2] 5a }

  condition:
    any of them
}