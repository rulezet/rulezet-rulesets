rule TTP_XOR_MULT_DOSStub_ac6a {
  strings:
    $key_ac6a = { f8 02 [2] 8c 1a [2] cb 18 [2] 8c 09 [2] c2 05 [2] ce 0f [2] d9 04 [2] c2 4a [2] ff }

  condition:
    any of them
}