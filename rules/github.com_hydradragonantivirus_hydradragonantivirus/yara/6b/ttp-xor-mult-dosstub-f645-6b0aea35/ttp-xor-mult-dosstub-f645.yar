rule TTP_XOR_MULT_DOSStub_f645 {
  strings:
    $key_f645 = { a2 2d [2] d6 35 [2] 91 37 [2] d6 26 [2] 98 2a [2] 94 20 [2] 83 2b [2] 98 65 [2] a5 }

  condition:
    any of them
}