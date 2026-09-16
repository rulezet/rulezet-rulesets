rule TTP_XOR_MULT_DOSStub_767a {
  strings:
    $key_767a = { 22 12 [2] 56 0a [2] 11 08 [2] 56 19 [2] 18 15 [2] 14 1f [2] 03 14 [2] 18 5a [2] 25 }

  condition:
    any of them
}