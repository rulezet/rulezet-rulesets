rule TTP_XOR_MULT_DOSStub_4909 {
  strings:
    $key_4909 = { 1d 61 [2] 69 79 [2] 2e 7b [2] 69 6a [2] 27 66 [2] 2b 6c [2] 3c 67 [2] 27 29 [2] 1a }

  condition:
    any of them
}