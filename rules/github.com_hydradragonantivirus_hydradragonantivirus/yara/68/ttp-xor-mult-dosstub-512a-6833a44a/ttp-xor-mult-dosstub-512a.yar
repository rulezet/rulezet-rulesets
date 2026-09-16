rule TTP_XOR_MULT_DOSStub_512a {
  strings:
    $key_512a = { 05 42 [2] 71 5a [2] 36 58 [2] 71 49 [2] 3f 45 [2] 33 4f [2] 24 44 [2] 3f 0a [2] 02 }

  condition:
    any of them
}