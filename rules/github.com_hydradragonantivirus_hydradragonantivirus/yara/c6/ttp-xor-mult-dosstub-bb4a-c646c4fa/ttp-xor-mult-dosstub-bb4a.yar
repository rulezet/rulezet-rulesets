rule TTP_XOR_MULT_DOSStub_bb4a {
  strings:
    $key_bb4a = { ef 22 [2] 9b 3a [2] dc 38 [2] 9b 29 [2] d5 25 [2] d9 2f [2] ce 24 [2] d5 6a [2] e8 }

  condition:
    any of them
}