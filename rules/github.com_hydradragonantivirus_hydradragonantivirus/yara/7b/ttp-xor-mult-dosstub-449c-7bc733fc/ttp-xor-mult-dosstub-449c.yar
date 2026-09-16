rule TTP_XOR_MULT_DOSStub_449c {
  strings:
    $key_449c = { 10 f4 [2] 64 ec [2] 23 ee [2] 64 ff [2] 2a f3 [2] 26 f9 [2] 31 f2 [2] 2a bc [2] 17 }

  condition:
    any of them
}