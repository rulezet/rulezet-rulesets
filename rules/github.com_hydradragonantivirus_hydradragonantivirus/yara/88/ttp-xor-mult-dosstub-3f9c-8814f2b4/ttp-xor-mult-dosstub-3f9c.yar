rule TTP_XOR_MULT_DOSStub_3f9c {
  strings:
    $key_3f9c = { 6b f4 [2] 1f ec [2] 58 ee [2] 1f ff [2] 51 f3 [2] 5d f9 [2] 4a f2 [2] 51 bc [2] 6c }

  condition:
    any of them
}