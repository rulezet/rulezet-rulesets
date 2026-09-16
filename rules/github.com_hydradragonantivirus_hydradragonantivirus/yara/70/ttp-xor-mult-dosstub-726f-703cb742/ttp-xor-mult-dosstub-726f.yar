rule TTP_XOR_MULT_DOSStub_726f {
  strings:
    $key_726f = { 26 07 [2] 52 1f [2] 15 1d [2] 52 0c [2] 1c 00 [2] 10 0a [2] 07 01 [2] 1c 4f [2] 21 }

  condition:
    any of them
}