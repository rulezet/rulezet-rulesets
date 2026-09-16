rule TTP_XOR_MULT_DOSStub_517f {
  strings:
    $key_517f = { 05 17 [2] 71 0f [2] 36 0d [2] 71 1c [2] 3f 10 [2] 33 1a [2] 24 11 [2] 3f 5f [2] 02 }

  condition:
    any of them
}