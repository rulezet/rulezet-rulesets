rule TTP_XOR_MULT_DOSStub_f638 {
  strings:
    $key_f638 = { a2 50 [2] d6 48 [2] 91 4a [2] d6 5b [2] 98 57 [2] 94 5d [2] 83 56 [2] 98 18 [2] a5 }

  condition:
    any of them
}