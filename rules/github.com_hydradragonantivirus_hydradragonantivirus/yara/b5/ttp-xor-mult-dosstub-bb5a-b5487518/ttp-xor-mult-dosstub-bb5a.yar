rule TTP_XOR_MULT_DOSStub_bb5a {
  strings:
    $key_bb5a = { ef 32 [2] 9b 2a [2] dc 28 [2] 9b 39 [2] d5 35 [2] d9 3f [2] ce 34 [2] d5 7a [2] e8 }

  condition:
    any of them
}