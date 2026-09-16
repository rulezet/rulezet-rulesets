rule TTP_XOR_MULT_DOSStub_767f {
  strings:
    $key_767f = { 22 17 [2] 56 0f [2] 11 0d [2] 56 1c [2] 18 10 [2] 14 1a [2] 03 11 [2] 18 5f [2] 25 }

  condition:
    any of them
}