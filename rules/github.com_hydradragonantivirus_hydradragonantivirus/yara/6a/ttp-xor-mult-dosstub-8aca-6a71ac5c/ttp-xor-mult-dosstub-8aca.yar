rule TTP_XOR_MULT_DOSStub_8aca {
  strings:
    $key_8aca = { de a2 [2] aa ba [2] ed b8 [2] aa a9 [2] e4 a5 [2] e8 af [2] ff a4 [2] e4 ea [2] d9 }

  condition:
    any of them
}