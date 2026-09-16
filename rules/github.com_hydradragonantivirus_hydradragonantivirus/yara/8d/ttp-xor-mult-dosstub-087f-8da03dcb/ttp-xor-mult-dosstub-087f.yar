rule TTP_XOR_MULT_DOSStub_087f {
  strings:
    $key_087f = { 5c 17 [2] 28 0f [2] 6f 0d [2] 28 1c [2] 66 10 [2] 6a 1a [2] 7d 11 [2] 66 5f [2] 5b }

  condition:
    any of them
}