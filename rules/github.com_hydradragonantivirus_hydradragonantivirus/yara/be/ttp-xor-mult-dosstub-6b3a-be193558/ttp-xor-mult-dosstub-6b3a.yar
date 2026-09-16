rule TTP_XOR_MULT_DOSStub_6b3a {
  strings:
    $key_6b3a = { 3f 52 [2] 4b 4a [2] 0c 48 [2] 4b 59 [2] 05 55 [2] 09 5f [2] 1e 54 [2] 05 1a [2] 38 }

  condition:
    any of them
}