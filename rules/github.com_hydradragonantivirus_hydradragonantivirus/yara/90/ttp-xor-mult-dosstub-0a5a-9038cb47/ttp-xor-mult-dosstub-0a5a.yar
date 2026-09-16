rule TTP_XOR_MULT_DOSStub_0a5a {
  strings:
    $key_0a5a = { 5e 32 [2] 2a 2a [2] 6d 28 [2] 2a 39 [2] 64 35 [2] 68 3f [2] 7f 34 [2] 64 7a [2] 59 }

  condition:
    any of them
}