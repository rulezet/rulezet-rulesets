rule TTP_XOR_MULT_DOSStub_f697 {
  strings:
    $key_f697 = { a2 ff [2] d6 e7 [2] 91 e5 [2] d6 f4 [2] 98 f8 [2] 94 f2 [2] 83 f9 [2] 98 b7 [2] a5 }

  condition:
    any of them
}