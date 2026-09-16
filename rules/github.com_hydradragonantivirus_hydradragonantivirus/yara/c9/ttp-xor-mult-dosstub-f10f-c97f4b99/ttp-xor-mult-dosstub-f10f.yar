rule TTP_XOR_MULT_DOSStub_f10f {
  strings:
    $key_f10f = { a5 67 [2] d1 7f [2] 96 7d [2] d1 6c [2] 9f 60 [2] 93 6a [2] 84 61 [2] 9f 2f [2] a2 }

  condition:
    any of them
}