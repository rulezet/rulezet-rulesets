rule TTP_XOR_MULT_DOSStub_f1e3 {
  strings:
    $key_f1e3 = { a5 8b [2] d1 93 [2] 96 91 [2] d1 80 [2] 9f 8c [2] 93 86 [2] 84 8d [2] 9f c3 [2] a2 }

  condition:
    any of them
}