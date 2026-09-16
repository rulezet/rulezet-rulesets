rule TTP_XOR_MULT_DOSStub_f59c {
  strings:
    $key_f59c = { a1 f4 [2] d5 ec [2] 92 ee [2] d5 ff [2] 9b f3 [2] 97 f9 [2] 80 f2 [2] 9b bc [2] a6 }

  condition:
    any of them
}