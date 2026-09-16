rule TTP_XOR_MULT_DOSStub_500e {
  strings:
    $key_500e = { 04 66 [2] 70 7e [2] 37 7c [2] 70 6d [2] 3e 61 [2] 32 6b [2] 25 60 [2] 3e 2e [2] 03 }

  condition:
    any of them
}