rule TTP_XOR_MULT_DOSStub_387f {
  strings:
    $key_387f = { 6c 17 [2] 18 0f [2] 5f 0d [2] 18 1c [2] 56 10 [2] 5a 1a [2] 4d 11 [2] 56 5f [2] 6b }

  condition:
    any of them
}