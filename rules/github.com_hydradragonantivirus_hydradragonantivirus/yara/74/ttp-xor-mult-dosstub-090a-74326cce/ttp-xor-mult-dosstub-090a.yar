rule TTP_XOR_MULT_DOSStub_090a {
  strings:
    $key_090a = { 5d 62 [2] 29 7a [2] 6e 78 [2] 29 69 [2] 67 65 [2] 6b 6f [2] 7c 64 [2] 67 2a [2] 5a }

  condition:
    any of them
}