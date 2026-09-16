rule TTP_XOR_MULT_DOSStub_0b0a {
  strings:
    $key_0b0a = { 5f 62 [2] 2b 7a [2] 6c 78 [2] 2b 69 [2] 65 65 [2] 69 6f [2] 7e 64 [2] 65 2a [2] 58 }

  condition:
    any of them
}