rule TTP_XOR_MULT_DOSStub_0a2a {
  strings:
    $key_0a2a = { 5e 42 [2] 2a 5a [2] 6d 58 [2] 2a 49 [2] 64 45 [2] 68 4f [2] 7f 44 [2] 64 0a [2] 59 }

  condition:
    any of them
}