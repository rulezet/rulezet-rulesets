rule TTP_XOR_MULT_DOSStub_170e {
  strings:
    $key_170e = { 43 66 [2] 37 7e [2] 70 7c [2] 37 6d [2] 79 61 [2] 75 6b [2] 62 60 [2] 79 2e [2] 44 }

  condition:
    any of them
}