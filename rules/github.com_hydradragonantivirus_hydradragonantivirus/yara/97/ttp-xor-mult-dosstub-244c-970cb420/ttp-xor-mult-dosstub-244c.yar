rule TTP_XOR_MULT_DOSStub_244c {
  strings:
    $key_244c = { 70 24 [2] 04 3c [2] 43 3e [2] 04 2f [2] 4a 23 [2] 46 29 [2] 51 22 [2] 4a 6c [2] 77 }

  condition:
    any of them
}