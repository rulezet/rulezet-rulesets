rule TTP_XOR_MULT_DOSStub_634c {
  strings:
    $key_634c = { 37 24 [2] 43 3c [2] 04 3e [2] 43 2f [2] 0d 23 [2] 01 29 [2] 16 22 [2] 0d 6c [2] 30 }

  condition:
    any of them
}