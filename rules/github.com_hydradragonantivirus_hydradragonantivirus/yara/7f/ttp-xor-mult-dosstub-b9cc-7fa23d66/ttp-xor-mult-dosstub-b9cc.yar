rule TTP_XOR_MULT_DOSStub_b9cc {
  strings:
    $key_b9cc = { ed a4 [2] 99 bc [2] de be [2] 99 af [2] d7 a3 [2] db a9 [2] cc a2 [2] d7 ec [2] ea }

  condition:
    any of them
}