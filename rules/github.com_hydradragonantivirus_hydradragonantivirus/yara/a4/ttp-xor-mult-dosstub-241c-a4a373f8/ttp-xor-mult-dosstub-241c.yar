rule TTP_XOR_MULT_DOSStub_241c {
  strings:
    $key_241c = { 70 74 [2] 04 6c [2] 43 6e [2] 04 7f [2] 4a 73 [2] 46 79 [2] 51 72 [2] 4a 3c [2] 77 }

  condition:
    any of them
}