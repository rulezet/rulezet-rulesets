rule TTP_XOR_MULT_DOSStub_2e3a {
  strings:
    $key_2e3a = { 7a 52 [2] 0e 4a [2] 49 48 [2] 0e 59 [2] 40 55 [2] 4c 5f [2] 5b 54 [2] 40 1a [2] 7d }

  condition:
    any of them
}