rule TTP_XOR_MULT_DOSStub_f0e3 {
  strings:
    $key_f0e3 = { a4 8b [2] d0 93 [2] 97 91 [2] d0 80 [2] 9e 8c [2] 92 86 [2] 85 8d [2] 9e c3 [2] a3 }

  condition:
    any of them
}