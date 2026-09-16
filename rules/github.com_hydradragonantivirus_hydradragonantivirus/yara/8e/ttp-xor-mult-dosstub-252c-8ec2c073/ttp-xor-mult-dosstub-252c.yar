rule TTP_XOR_MULT_DOSStub_252c {
  strings:
    $key_252c = { 71 44 [2] 05 5c [2] 42 5e [2] 05 4f [2] 4b 43 [2] 47 49 [2] 50 42 [2] 4b 0c [2] 76 }

  condition:
    any of them
}