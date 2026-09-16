rule TTP_XOR_MULT_DOSStub_194e {
  strings:
    $key_194e = { 4d 26 [2] 39 3e [2] 7e 3c [2] 39 2d [2] 77 21 [2] 7b 2b [2] 6c 20 [2] 77 6e [2] 4a }

  condition:
    any of them
}