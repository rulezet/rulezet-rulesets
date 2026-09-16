rule TTP_XOR_MULT_DOSStub_017a {
  strings:
    $key_017a = { 55 12 [2] 21 0a [2] 66 08 [2] 21 19 [2] 6f 15 [2] 63 1f [2] 74 14 [2] 6f 5a [2] 52 }

  condition:
    any of them
}