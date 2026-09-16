rule TTP_XOR_MULT_DOSStub_8acb {
  strings:
    $key_8acb = { de a3 [2] aa bb [2] ed b9 [2] aa a8 [2] e4 a4 [2] e8 ae [2] ff a5 [2] e4 eb [2] d9 }

  condition:
    any of them
}