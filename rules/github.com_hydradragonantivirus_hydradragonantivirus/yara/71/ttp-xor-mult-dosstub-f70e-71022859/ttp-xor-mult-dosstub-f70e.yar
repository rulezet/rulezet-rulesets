rule TTP_XOR_MULT_DOSStub_f70e {
  strings:
    $key_f70e = { a3 66 [2] d7 7e [2] 90 7c [2] d7 6d [2] 99 61 [2] 95 6b [2] 82 60 [2] 99 2e [2] a4 }

  condition:
    any of them
}