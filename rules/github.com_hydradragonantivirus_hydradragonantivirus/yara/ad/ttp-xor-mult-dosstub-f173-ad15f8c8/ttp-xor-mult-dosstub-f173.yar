rule TTP_XOR_MULT_DOSStub_f173 {
  strings:
    $key_f173 = { a5 1b [2] d1 03 [2] 96 01 [2] d1 10 [2] 9f 1c [2] 93 16 [2] 84 1d [2] 9f 53 [2] a2 }

  condition:
    any of them
}