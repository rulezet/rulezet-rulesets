rule TTP_XOR_MULT_DOSStub_f11e {
  strings:
    $key_f11e = { a5 76 [2] d1 6e [2] 96 6c [2] d1 7d [2] 9f 71 [2] 93 7b [2] 84 70 [2] 9f 3e [2] a2 }

  condition:
    any of them
}