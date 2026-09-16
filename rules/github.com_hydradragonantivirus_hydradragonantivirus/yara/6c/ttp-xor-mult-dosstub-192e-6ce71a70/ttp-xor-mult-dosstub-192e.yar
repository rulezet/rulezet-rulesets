rule TTP_XOR_MULT_DOSStub_192e {
  strings:
    $key_192e = { 4d 46 [2] 39 5e [2] 7e 5c [2] 39 4d [2] 77 41 [2] 7b 4b [2] 6c 40 [2] 77 0e [2] 4a }

  condition:
    any of them
}