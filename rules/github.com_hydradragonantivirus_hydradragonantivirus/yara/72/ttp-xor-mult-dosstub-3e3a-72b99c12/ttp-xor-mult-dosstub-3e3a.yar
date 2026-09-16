rule TTP_XOR_MULT_DOSStub_3e3a {
  strings:
    $key_3e3a = { 6a 52 [2] 1e 4a [2] 59 48 [2] 1e 59 [2] 50 55 [2] 5c 5f [2] 4b 54 [2] 50 1a [2] 6d }

  condition:
    any of them
}