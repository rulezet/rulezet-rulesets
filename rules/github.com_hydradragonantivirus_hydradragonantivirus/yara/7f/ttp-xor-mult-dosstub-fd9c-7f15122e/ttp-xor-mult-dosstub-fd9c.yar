rule TTP_XOR_MULT_DOSStub_fd9c {
  strings:
    $key_fd9c = { a9 f4 [2] dd ec [2] 9a ee [2] dd ff [2] 93 f3 [2] 9f f9 [2] 88 f2 [2] 93 bc [2] ae }

  condition:
    any of them
}