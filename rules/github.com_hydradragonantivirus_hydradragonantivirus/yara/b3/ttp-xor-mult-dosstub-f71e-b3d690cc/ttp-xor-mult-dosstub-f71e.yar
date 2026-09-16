rule TTP_XOR_MULT_DOSStub_f71e {
  strings:
    $key_f71e = { a3 76 [2] d7 6e [2] 90 6c [2] d7 7d [2] 99 71 [2] 95 7b [2] 82 70 [2] 99 3e [2] a4 }

  condition:
    any of them
}