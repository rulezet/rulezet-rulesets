rule TTP_XOR_MULT_DOSStub_295a {
  strings:
    $key_295a = { 7d 32 [2] 09 2a [2] 4e 28 [2] 09 39 [2] 47 35 [2] 4b 3f [2] 5c 34 [2] 47 7a [2] 7a }

  condition:
    any of them
}