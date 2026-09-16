rule TTP_XOR_MULT_DOSStub_5b0e {
  strings:
    $key_5b0e = { 0f 66 [2] 7b 7e [2] 3c 7c [2] 7b 6d [2] 35 61 [2] 39 6b [2] 2e 60 [2] 35 2e [2] 08 }

  condition:
    any of them
}