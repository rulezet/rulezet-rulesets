rule TTP_XOR_MULT_DOSStub_056f {
  strings:
    $key_056f = { 51 07 [2] 25 1f [2] 62 1d [2] 25 0c [2] 6b 00 [2] 67 0a [2] 70 01 [2] 6b 4f [2] 56 }

  condition:
    any of them
}