rule TTP_XOR_MULT_DOSStub_8a8d {
  strings:
    $key_8a8d = { de e5 [2] aa fd [2] ed ff [2] aa ee [2] e4 e2 [2] e8 e8 [2] ff e3 [2] e4 ad [2] d9 }

  condition:
    any of them
}