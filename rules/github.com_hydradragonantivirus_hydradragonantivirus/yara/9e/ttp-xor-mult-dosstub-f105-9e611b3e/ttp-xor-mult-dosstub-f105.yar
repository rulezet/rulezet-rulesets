rule TTP_XOR_MULT_DOSStub_f105 {
  strings:
    $key_f105 = { a5 6d [2] d1 75 [2] 96 77 [2] d1 66 [2] 9f 6a [2] 93 60 [2] 84 6b [2] 9f 25 [2] a2 }

  condition:
    any of them
}