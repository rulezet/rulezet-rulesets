rule TTP_XOR_MULT_DOSStub_210e {
  strings:
    $key_210e = { 75 66 [2] 01 7e [2] 46 7c [2] 01 6d [2] 4f 61 [2] 43 6b [2] 54 60 [2] 4f 2e [2] 72 }

  condition:
    any of them
}