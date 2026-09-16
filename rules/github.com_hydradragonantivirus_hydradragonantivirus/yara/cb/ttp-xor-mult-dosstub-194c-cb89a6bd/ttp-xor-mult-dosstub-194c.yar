rule TTP_XOR_MULT_DOSStub_194c {
  strings:
    $key_194c = { 4d 24 [2] 39 3c [2] 7e 3e [2] 39 2f [2] 77 23 [2] 7b 29 [2] 6c 22 [2] 77 6c [2] 4a }

  condition:
    any of them
}