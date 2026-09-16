rule TTP_XOR_MULT_DOSStub_f635 {
  strings:
    $key_f635 = { a2 5d [2] d6 45 [2] 91 47 [2] d6 56 [2] 98 5a [2] 94 50 [2] 83 5b [2] 98 15 [2] a5 }

  condition:
    any of them
}