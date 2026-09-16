rule TTP_XOR_MULT_DOSStub_404c {
  strings:
    $key_404c = { 14 24 [2] 60 3c [2] 27 3e [2] 60 2f [2] 2e 23 [2] 22 29 [2] 35 22 [2] 2e 6c [2] 13 }

  condition:
    any of them
}