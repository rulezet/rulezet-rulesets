rule TTP_XOR_MULT_DOSStub_257c {
  strings:
    $key_257c = { 71 14 [2] 05 0c [2] 42 0e [2] 05 1f [2] 4b 13 [2] 47 19 [2] 50 12 [2] 4b 5c [2] 76 }

  condition:
    any of them
}