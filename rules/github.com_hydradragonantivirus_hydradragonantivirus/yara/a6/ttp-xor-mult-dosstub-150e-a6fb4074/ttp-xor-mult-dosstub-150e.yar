rule TTP_XOR_MULT_DOSStub_150e {
  strings:
    $key_150e = { 41 66 [2] 35 7e [2] 72 7c [2] 35 6d [2] 7b 61 [2] 77 6b [2] 60 60 [2] 7b 2e [2] 46 }

  condition:
    any of them
}