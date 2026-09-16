rule TTP_XOR_MULT_DOSStub_104c {
  strings:
    $key_104c = { 44 24 [2] 30 3c [2] 77 3e [2] 30 2f [2] 7e 23 [2] 72 29 [2] 65 22 [2] 7e 6c [2] 43 }

  condition:
    any of them
}