rule TTP_XOR_MULT_DOSStub_8ace {
  strings:
    $key_8ace = { de a6 [2] aa be [2] ed bc [2] aa ad [2] e4 a1 [2] e8 ab [2] ff a0 [2] e4 ee [2] d9 }

  condition:
    any of them
}