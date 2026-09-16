rule TTP_XOR_MULT_DOSStub_f49c {
  strings:
    $key_f49c = { a0 f4 [2] d4 ec [2] 93 ee [2] d4 ff [2] 9a f3 [2] 96 f9 [2] 81 f2 [2] 9a bc [2] a7 }

  condition:
    any of them
}