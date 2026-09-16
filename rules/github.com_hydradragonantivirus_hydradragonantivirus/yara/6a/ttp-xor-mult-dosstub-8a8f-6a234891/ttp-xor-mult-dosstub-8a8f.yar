rule TTP_XOR_MULT_DOSStub_8a8f {
  strings:
    $key_8a8f = { de e7 [2] aa ff [2] ed fd [2] aa ec [2] e4 e0 [2] e8 ea [2] ff e1 [2] e4 af [2] d9 }

  condition:
    any of them
}