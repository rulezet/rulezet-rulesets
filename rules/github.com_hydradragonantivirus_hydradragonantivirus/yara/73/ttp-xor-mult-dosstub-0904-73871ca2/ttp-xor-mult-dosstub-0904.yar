rule TTP_XOR_MULT_DOSStub_0904 {
  strings:
    $key_0904 = { 5d 6c [2] 29 74 [2] 6e 76 [2] 29 67 [2] 67 6b [2] 6b 61 [2] 7c 6a [2] 67 24 [2] 5a }

  condition:
    any of them
}