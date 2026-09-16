rule TTP_XOR_MULT_DOSStub_193e {
  strings:
    $key_193e = { 4d 56 [2] 39 4e [2] 7e 4c [2] 39 5d [2] 77 51 [2] 7b 5b [2] 6c 50 [2] 77 1e [2] 4a }

  condition:
    any of them
}