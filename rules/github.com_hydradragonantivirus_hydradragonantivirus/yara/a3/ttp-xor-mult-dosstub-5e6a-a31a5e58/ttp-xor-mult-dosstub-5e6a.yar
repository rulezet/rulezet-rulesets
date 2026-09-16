rule TTP_XOR_MULT_DOSStub_5e6a {
  strings:
    $key_5e6a = { 0a 02 [2] 7e 1a [2] 39 18 [2] 7e 09 [2] 30 05 [2] 3c 0f [2] 2b 04 [2] 30 4a [2] 0d }

  condition:
    any of them
}