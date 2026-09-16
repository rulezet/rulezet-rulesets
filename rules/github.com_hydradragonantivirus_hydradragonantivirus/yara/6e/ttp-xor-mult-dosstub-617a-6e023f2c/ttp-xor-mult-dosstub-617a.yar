rule TTP_XOR_MULT_DOSStub_617a {
  strings:
    $key_617a = { 35 12 [2] 41 0a [2] 06 08 [2] 41 19 [2] 0f 15 [2] 03 1f [2] 14 14 [2] 0f 5a [2] 32 }

  condition:
    any of them
}