rule TTP_XOR_MULT_DOSStub_295e {
  strings:
    $key_295e = { 7d 36 [2] 09 2e [2] 4e 2c [2] 09 3d [2] 47 31 [2] 4b 3b [2] 5c 30 [2] 47 7e [2] 7a }

  condition:
    any of them
}