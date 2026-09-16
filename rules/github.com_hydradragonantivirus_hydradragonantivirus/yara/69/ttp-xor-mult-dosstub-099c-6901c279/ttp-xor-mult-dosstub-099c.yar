rule TTP_XOR_MULT_DOSStub_099c {
  strings:
    $key_099c = { 5d f4 [2] 29 ec [2] 6e ee [2] 29 ff [2] 67 f3 [2] 6b f9 [2] 7c f2 [2] 67 bc [2] 5a }

  condition:
    any of them
}