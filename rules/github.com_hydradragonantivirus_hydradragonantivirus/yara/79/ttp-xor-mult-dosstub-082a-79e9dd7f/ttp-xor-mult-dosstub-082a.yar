rule TTP_XOR_MULT_DOSStub_082a {
  strings:
    $key_082a = { 5c 42 [2] 28 5a [2] 6f 58 [2] 28 49 [2] 66 45 [2] 6a 4f [2] 7d 44 [2] 66 0a [2] 5b }

  condition:
    any of them
}