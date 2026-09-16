rule TTP_XOR_MULT_DOSStub_f9cc {
  strings:
    $key_f9cc = { ad a4 [2] d9 bc [2] 9e be [2] d9 af [2] 97 a3 [2] 9b a9 [2] 8c a2 [2] 97 ec [2] aa }

  condition:
    any of them
}