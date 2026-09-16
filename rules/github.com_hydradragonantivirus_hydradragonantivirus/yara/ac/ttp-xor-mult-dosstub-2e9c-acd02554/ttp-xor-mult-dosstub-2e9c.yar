rule TTP_XOR_MULT_DOSStub_2e9c {
  strings:
    $key_2e9c = { 7a f4 [2] 0e ec [2] 49 ee [2] 0e ff [2] 40 f3 [2] 4c f9 [2] 5b f2 [2] 40 bc [2] 7d }

  condition:
    any of them
}