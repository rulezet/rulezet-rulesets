rule TTP_XOR_MULT_DOSStub_597c {
  strings:
    $key_597c = { 0d 14 [2] 79 0c [2] 3e 0e [2] 79 1f [2] 37 13 [2] 3b 19 [2] 2c 12 [2] 37 5c [2] 0a }

  condition:
    any of them
}