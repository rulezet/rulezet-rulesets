rule TTP_XOR_MULT_DOSStub_385a {
  strings:
    $key_385a = { 6c 32 [2] 18 2a [2] 5f 28 [2] 18 39 [2] 56 35 [2] 5a 3f [2] 4d 34 [2] 56 7a [2] 6b }

  condition:
    any of them
}