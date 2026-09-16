rule TTP_XOR_MULT_DOSStub_f40f {
  strings:
    $key_f40f = { a0 67 [2] d4 7f [2] 93 7d [2] d4 6c [2] 9a 60 [2] 96 6a [2] 81 61 [2] 9a 2f [2] a7 }

  condition:
    any of them
}