rule TTP_XOR_MULT_DOSStub_071c {
  strings:
    $key_071c = { 53 74 [2] 27 6c [2] 60 6e [2] 27 7f [2] 69 73 [2] 65 79 [2] 72 72 [2] 69 3c [2] 54 }

  condition:
    any of them
}