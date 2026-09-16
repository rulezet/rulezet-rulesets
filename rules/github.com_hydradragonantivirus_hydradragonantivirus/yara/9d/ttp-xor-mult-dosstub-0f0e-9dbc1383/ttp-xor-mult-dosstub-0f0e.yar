rule TTP_XOR_MULT_DOSStub_0f0e {
  strings:
    $key_0f0e = { 5b 66 [2] 2f 7e [2] 68 7c [2] 2f 6d [2] 61 61 [2] 6d 6b [2] 7a 60 [2] 61 2e [2] 5c }

  condition:
    any of them
}