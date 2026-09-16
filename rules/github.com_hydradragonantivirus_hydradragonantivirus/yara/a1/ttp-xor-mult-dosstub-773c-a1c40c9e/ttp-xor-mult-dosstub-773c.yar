rule TTP_XOR_MULT_DOSStub_773c {
  strings:
    $key_773c = { 23 54 [2] 57 4c [2] 10 4e [2] 57 5f [2] 19 53 [2] 15 59 [2] 02 52 [2] 19 1c [2] 24 }

  condition:
    any of them
}