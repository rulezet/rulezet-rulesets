rule TTP_XOR_MULT_DOSStub_382a {
  strings:
    $key_382a = { 6c 42 [2] 18 5a [2] 5f 58 [2] 18 49 [2] 56 45 [2] 5a 4f [2] 4d 44 [2] 56 0a [2] 6b }

  condition:
    any of them
}