rule TTP_XOR_MULT_DOSStub_012a {
  strings:
    $key_012a = { 55 42 [2] 21 5a [2] 66 58 [2] 21 49 [2] 6f 45 [2] 63 4f [2] 74 44 [2] 6f 0a [2] 52 }

  condition:
    any of them
}