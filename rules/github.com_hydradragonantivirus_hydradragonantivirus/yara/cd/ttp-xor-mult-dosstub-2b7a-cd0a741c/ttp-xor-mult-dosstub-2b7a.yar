rule TTP_XOR_MULT_DOSStub_2b7a {
  strings:
    $key_2b7a = { 7f 12 [2] 0b 0a [2] 4c 08 [2] 0b 19 [2] 45 15 [2] 49 1f [2] 5e 14 [2] 45 5a [2] 78 }

  condition:
    any of them
}