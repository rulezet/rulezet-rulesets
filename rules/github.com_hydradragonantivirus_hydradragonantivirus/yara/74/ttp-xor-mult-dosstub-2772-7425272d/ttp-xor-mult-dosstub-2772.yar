rule TTP_XOR_MULT_DOSStub_2772 {
  strings:
    $key_2772 = { 73 1a [2] 07 02 [2] 40 00 [2] 07 11 [2] 49 1d [2] 45 17 [2] 52 1c [2] 49 52 [2] 74 }

  condition:
    any of them
}