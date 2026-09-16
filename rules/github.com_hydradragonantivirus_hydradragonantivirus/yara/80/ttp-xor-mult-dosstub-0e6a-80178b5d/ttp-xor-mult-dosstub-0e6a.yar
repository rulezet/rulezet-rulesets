rule TTP_XOR_MULT_DOSStub_0e6a {
  strings:
    $key_0e6a = { 5a 02 [2] 2e 1a [2] 69 18 [2] 2e 09 [2] 60 05 [2] 6c 0f [2] 7b 04 [2] 60 4a [2] 5d }

  condition:
    any of them
}