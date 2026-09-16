rule TTP_XOR_MULT_DOSStub_5e09 {
  strings:
    $key_5e09 = { 0a 61 [2] 7e 79 [2] 39 7b [2] 7e 6a [2] 30 66 [2] 3c 6c [2] 2b 67 [2] 30 29 [2] 0d }

  condition:
    any of them
}