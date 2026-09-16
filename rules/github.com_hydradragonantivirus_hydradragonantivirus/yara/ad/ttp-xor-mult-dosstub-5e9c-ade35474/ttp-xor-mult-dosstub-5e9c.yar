rule TTP_XOR_MULT_DOSStub_5e9c {
  strings:
    $key_5e9c = { 0a f4 [2] 7e ec [2] 39 ee [2] 7e ff [2] 30 f3 [2] 3c f9 [2] 2b f2 [2] 30 bc [2] 0d }

  condition:
    any of them
}