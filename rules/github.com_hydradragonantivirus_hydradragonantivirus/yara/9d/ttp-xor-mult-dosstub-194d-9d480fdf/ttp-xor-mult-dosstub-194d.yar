rule TTP_XOR_MULT_DOSStub_194d {
  strings:
    $key_194d = { 4d 25 [2] 39 3d [2] 7e 3f [2] 39 2e [2] 77 22 [2] 7b 28 [2] 6c 23 [2] 77 6d [2] 4a }

  condition:
    any of them
}