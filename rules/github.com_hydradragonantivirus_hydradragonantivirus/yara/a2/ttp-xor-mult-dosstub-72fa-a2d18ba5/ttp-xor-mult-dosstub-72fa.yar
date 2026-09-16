rule TTP_XOR_MULT_DOSStub_72fa {
  strings:
    $key_72fa = { 26 92 [2] 52 8a [2] 15 88 [2] 52 99 [2] 1c 95 [2] 10 9f [2] 07 94 [2] 1c da [2] 21 }

  condition:
    any of them
}