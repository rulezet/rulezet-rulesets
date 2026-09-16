rule TTP_XOR_MULT_DOSStub_154c {
  strings:
    $key_154c = { 41 24 [2] 35 3c [2] 72 3e [2] 35 2f [2] 7b 23 [2] 77 29 [2] 60 22 [2] 7b 6c [2] 46 }

  condition:
    any of them
}