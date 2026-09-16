rule TTP_XOR_MULT_DOSStub_8aab {
  strings:
    $key_8aab = { de c3 [2] aa db [2] ed d9 [2] aa c8 [2] e4 c4 [2] e8 ce [2] ff c5 [2] e4 8b [2] d9 }

  condition:
    any of them
}