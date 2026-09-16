rule TTP_XOR_MULT_DOSStub_190e {
  strings:
    $key_190e = { 4d 66 [2] 39 7e [2] 7e 7c [2] 39 6d [2] 77 61 [2] 7b 6b [2] 6c 60 [2] 77 2e [2] 4a }

  condition:
    any of them
}