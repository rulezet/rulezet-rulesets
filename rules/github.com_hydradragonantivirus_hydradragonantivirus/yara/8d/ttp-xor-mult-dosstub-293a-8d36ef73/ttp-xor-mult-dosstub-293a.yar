rule TTP_XOR_MULT_DOSStub_293a {
  strings:
    $key_293a = { 7d 52 [2] 09 4a [2] 4e 48 [2] 09 59 [2] 47 55 [2] 4b 5f [2] 5c 54 [2] 47 1a [2] 7a }

  condition:
    any of them
}