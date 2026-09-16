rule TTP_XOR_MULT_DOSStub_253a {
  strings:
    $key_253a = { 71 52 [2] 05 4a [2] 42 48 [2] 05 59 [2] 4b 55 [2] 47 5f [2] 50 54 [2] 4b 1a [2] 76 }

  condition:
    any of them
}