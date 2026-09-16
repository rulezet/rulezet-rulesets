rule TTP_XOR_MULT_DOSStub_151c {
  strings:
    $key_151c = { 41 74 [2] 35 6c [2] 72 6e [2] 35 7f [2] 7b 73 [2] 77 79 [2] 60 72 [2] 7b 3c [2] 46 }

  condition:
    any of them
}