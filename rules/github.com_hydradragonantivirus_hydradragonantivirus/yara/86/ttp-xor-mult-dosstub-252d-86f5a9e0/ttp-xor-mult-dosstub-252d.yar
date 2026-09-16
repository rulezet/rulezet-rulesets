rule TTP_XOR_MULT_DOSStub_252d {
  strings:
    $key_252d = { 71 45 [2] 05 5d [2] 42 5f [2] 05 4e [2] 4b 42 [2] 47 48 [2] 50 43 [2] 4b 0d [2] 76 }

  condition:
    any of them
}