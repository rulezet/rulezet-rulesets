rule TTP_XOR_MULT_DOSStub_7b0e {
  strings:
    $key_7b0e = { 2f 66 [2] 5b 7e [2] 1c 7c [2] 5b 6d [2] 15 61 [2] 19 6b [2] 0e 60 [2] 15 2e [2] 28 }

  condition:
    any of them
}