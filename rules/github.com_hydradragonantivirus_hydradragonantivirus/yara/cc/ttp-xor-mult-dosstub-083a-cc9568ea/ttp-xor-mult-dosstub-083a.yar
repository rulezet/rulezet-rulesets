rule TTP_XOR_MULT_DOSStub_083a {
  strings:
    $key_083a = { 5c 52 [2] 28 4a [2] 6f 48 [2] 28 59 [2] 66 55 [2] 6a 5f [2] 7d 54 [2] 66 1a [2] 5b }

  condition:
    any of them
}