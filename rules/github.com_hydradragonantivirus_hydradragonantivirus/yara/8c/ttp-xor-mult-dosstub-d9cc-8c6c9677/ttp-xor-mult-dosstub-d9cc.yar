rule TTP_XOR_MULT_DOSStub_d9cc {
  strings:
    $key_d9cc = { 8d a4 [2] f9 bc [2] be be [2] f9 af [2] b7 a3 [2] bb a9 [2] ac a2 [2] b7 ec [2] 8a }

  condition:
    any of them
}