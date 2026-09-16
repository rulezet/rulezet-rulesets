rule TTP_XOR_MULT_DOSStub_383f {
  strings:
    $key_383f = { 6c 57 [2] 18 4f [2] 5f 4d [2] 18 5c [2] 56 50 [2] 5a 5a [2] 4d 51 [2] 56 1f [2] 6b }

  condition:
    any of them
}