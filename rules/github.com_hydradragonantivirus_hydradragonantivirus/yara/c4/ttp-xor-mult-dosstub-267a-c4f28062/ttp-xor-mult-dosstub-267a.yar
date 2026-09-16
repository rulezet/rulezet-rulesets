rule TTP_XOR_MULT_DOSStub_267a {
  strings:
    $key_267a = { 72 12 [2] 06 0a [2] 41 08 [2] 06 19 [2] 48 15 [2] 44 1f [2] 53 14 [2] 48 5a [2] 75 }

  condition:
    any of them
}