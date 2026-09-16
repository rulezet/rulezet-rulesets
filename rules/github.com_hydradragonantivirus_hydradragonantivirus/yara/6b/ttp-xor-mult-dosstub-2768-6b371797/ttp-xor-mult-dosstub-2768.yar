rule TTP_XOR_MULT_DOSStub_2768 {
  strings:
    $key_2768 = { 73 00 [2] 07 18 [2] 40 1a [2] 07 0b [2] 49 07 [2] 45 0d [2] 52 06 [2] 49 48 [2] 74 }

  condition:
    any of them
}