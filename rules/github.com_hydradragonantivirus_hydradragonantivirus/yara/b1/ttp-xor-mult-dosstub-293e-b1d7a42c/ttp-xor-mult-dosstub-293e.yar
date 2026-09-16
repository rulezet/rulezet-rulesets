rule TTP_XOR_MULT_DOSStub_293e {
  strings:
    $key_293e = { 7d 56 [2] 09 4e [2] 4e 4c [2] 09 5d [2] 47 51 [2] 4b 5b [2] 5c 50 [2] 47 1e [2] 7a }

  condition:
    any of them
}