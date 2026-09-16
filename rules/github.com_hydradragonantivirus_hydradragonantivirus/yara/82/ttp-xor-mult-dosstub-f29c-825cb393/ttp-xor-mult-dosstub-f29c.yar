rule TTP_XOR_MULT_DOSStub_f29c {
  strings:
    $key_f29c = { a6 f4 [2] d2 ec [2] 95 ee [2] d2 ff [2] 9c f3 [2] 90 f9 [2] 87 f2 [2] 9c bc [2] a1 }

  condition:
    any of them
}