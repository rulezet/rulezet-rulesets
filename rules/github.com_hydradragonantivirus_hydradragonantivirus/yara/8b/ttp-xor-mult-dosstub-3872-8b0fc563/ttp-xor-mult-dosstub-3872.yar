rule TTP_XOR_MULT_DOSStub_3872 {
  strings:
    $key_3872 = { 6c 1a [2] 18 02 [2] 5f 00 [2] 18 11 [2] 56 1d [2] 5a 17 [2] 4d 1c [2] 56 52 [2] 6b }

  condition:
    any of them
}