rule TTP_XOR_MULT_DOSStub_7e09 {
  strings:
    $key_7e09 = { 2a 61 [2] 5e 79 [2] 19 7b [2] 5e 6a [2] 10 66 [2] 1c 6c [2] 0b 67 [2] 10 29 [2] 2d }

  condition:
    any of them
}