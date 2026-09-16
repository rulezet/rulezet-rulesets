rule TTP_XOR_MULT_DOSStub_183e {
  strings:
    $key_183e = { 4c 56 [2] 38 4e [2] 7f 4c [2] 38 5d [2] 76 51 [2] 7a 5b [2] 6d 50 [2] 76 1e [2] 4b }

  condition:
    any of them
}