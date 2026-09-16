rule TTP_XOR_MULT_DOSStub_4f9c {
  strings:
    $key_4f9c = { 1b f4 [2] 6f ec [2] 28 ee [2] 6f ff [2] 21 f3 [2] 2d f9 [2] 3a f2 [2] 21 bc [2] 1c }

  condition:
    any of them
}